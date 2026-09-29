import http.client
import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.process = subprocess.Popen([sys.executable, "-m", "traceweave.server", "--port", "0", "--db", ":memory:"], cwd=Path(__file__).resolve().parents[1], env={**os.environ,"TRACEWEAVE_CLOUD_ENABLED":"0"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        line = cls.process.stdout.readline().strip()
        if not line.startswith("TraceWeave ready at"):
            cls.process.terminate()
            raise RuntimeError("Test server did not start: " + line)
        cls.port = int(line.rsplit(":", 1)[1])

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.communicate(timeout=5)

    def request(self, method, path, data=None, extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type":"application/json", **(extra or {})}
        conn.request(method,path,body=json.dumps(data) if data is not None else None,headers=headers)
        response = conn.getresponse()
        status, body = response.status, response.read()
        conn.close()
        return status, body

    # Checks that the local web UI and static assets are served successfully.
    def test_local_page_and_assets(self):
        for path in ("/", "/style.css", "/app.js"):
            status, body = self.request("GET", path)
            self.assertEqual(status,200)
            self.assertTrue(body)

    # Verifies the model endpoint reports availability and cloud remains disabled by default.
    def test_model_and_disabled_cloud_status(self):
        status, body = self.request("GET", "/api/model")
        self.assertEqual(status,200)
        self.assertTrue(json.loads(body)['available'])
        status, body = self.request("GET", "/api/cloud")
        self.assertEqual(status,200)
        self.assertFalse(json.loads(body)['configured'])
        self.assertEqual(self.request("POST", "/api/cloud/check", {})[0],400)
        self.assertEqual(self.request("POST", "/api/cloud/sync", {})[0],400)

    # Ensures cross-origin API calls are rejected before any mutation is processed.
    def test_cross_origin_request_rejected(self):
        status, _ = self.request("POST", "/api/demo", {"mode":"samples"}, {"Origin":"https://untrusted.example"})
        self.assertEqual(status,403)

    # Rejects non-JSON mutation payloads to keep the API contract strict.
    def test_non_json_mutation_rejected(self):
        status, _ = self.request("POST", "/api/demo", {"mode":"samples"}, {"Content-Type":"text/plain"})
        self.assertEqual(status,415)

    # Covers ingest, review, export, and re-ingestion behavior through the server API.
    def test_ingestion_review_export_and_reuse(self):
        raw = 'src=192.0.2.31 dst=198.51.100.32 action=deny\r\n'
        status, body = self.request("POST", "/api/ingest", {"source":"  uploaded-firewall  ","text":raw,"record_mode":"auto"})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["source"],"uploaded-firewall")
        _, body = self.request("GET", "/api/state")
        state = json.loads(body)
        row = next(r for r in state["events"] if r["source"] == "uploaded-firewall")
        self.assertEqual(row["status"],"needs_mapping")
        self.assertEqual(row["raw_text"],raw)
        status, body = self.request("POST", "/api/approve", {"source":row["source"],"fingerprint":row["fingerprint"],"mapping":row["suggested_mapping"]})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["normalized"],1)
        status, export = self.request("GET", "/api/export")
        self.assertEqual(status,200)
        self.assertTrue(all(json.loads(line)["status"] == "normalized" for line in export.splitlines()))
        self.assertTrue(any(json.loads(line)["source"] == "uploaded-firewall" for line in export.splitlines()))
        self.request("POST", "/api/ingest", {"source":"uploaded-firewall","text":raw.replace('192.0.2.31','192.0.2.33')})
        _, body = self.request("GET", "/api/state")
        rows = [r for r in json.loads(body)["events"] if r["source"] == "uploaded-firewall"]
        self.assertEqual(len(rows),2)
        self.assertTrue(all(r["status"] == "normalized" for r in rows))

    # Confirms demo and benchmark data are not exposed via server endpoints.
    def test_samples_are_not_exposed(self):
        self.assertEqual(self.request("POST", "/api/demo", {"mode":"samples"})[0],404)
        self.assertEqual(self.request("GET", "/demo-data.js")[0],404)
        self.assertEqual(self.request("GET", "/api/benchmark")[0],404)

    # Verifies pretty JSON records keep their original framing and format metadata.
    def test_automatic_framing_preserves_pretty_json(self):
        raw = '{\r\n  "src": "192.0.2.1",\r\n  "dst": "198.51.100.1",\r\n  "action": "deny"\r\n}\r\n'
        status, body = self.request("POST", "/api/ingest", {"source":"pretty-json", "text":raw, "record_mode":"auto"})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["ingested"],1)
        _, body = self.request("GET", "/api/state")
        row = next(r for r in json.loads(body)["events"] if r["source"] == "pretty-json")
        self.assertEqual(row["raw_text"],raw)
        self.assertEqual(row["format"],"JSON")

    # Checks NDJSON ingestion and rejects unsupported record_mode values.
    def test_auto_ndjson_and_bad_record_mode(self):
        raw = '{"src":"192.0.2.1","dst":"198.51.100.1","action":"deny"}\n' * 2
        status, body = self.request("POST", "/api/ingest", {"source":"ndjson", "text":raw, "record_mode":"auto"})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["ingested"],2)
        self.assertEqual(self.request("POST", "/api/ingest", {"text":raw,"record_mode":"invalid"})[0],400)

    # Ensures blank lines are ignored so empty events are not created.
    def test_blank_lines_do_not_create_empty_events(self):
        raw = 'src=192.0.2.1 dst=198.51.100.1 action=deny\r\n\r\n'
        status, body = self.request("POST", "/api/ingest", {"source":"blank-lines", "text":raw, "record_mode":"auto"})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["ingested"],1)
        _, body = self.request("GET", "/api/state")
        rows = [row for row in json.loads(body)["events"] if row["source"] == "blank-lines"]
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["raw_text"], 'src=192.0.2.1 dst=198.51.100.1 action=deny\r\n')

    # Confirms uploaded bytes and comma-containing values stay in KV format instead of being parsed as CSV.
    def test_uploaded_bytes_and_comma_values_are_not_mistaken_for_csv(self):
        raw = b'src=192.0.2.1 dst=198.51.100.2 action=deny note="one,two"\r\n' * 2
        status, body = self.request("POST", "/api/ingest", {"source":"file-bytes", "base64":base64.b64encode(raw).decode(), "record_mode":"auto"})
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["ingested"],2)
        _, body = self.request("GET", "/api/state")
        rows = [row for row in json.loads(body)["events"] if row["source"] == "file-bytes"]
        self.assertEqual(b''.join(base64.b64decode(row["raw_base64"]) for row in rows),raw)
        self.assertTrue(all(row["format"] == "KV" for row in rows))

    # Makes sure auto-detected CSV, XML, and invalid JSON payloads preserve their original bytes and metadata.
    def test_auto_csv_xml_and_invalid_json_keep_bytes(self):
        for source, raw, fmt in [('csv-auto','src,dst,action\r\n192.0.2.3,198.51.100.4,deny\r\n','CSV'),('xml-auto','<event>\n<src>192.0.2.3</src>\n<dst>198.51.100.4</dst>\n<action>deny</action>\n</event>','XML'),('duplicate-auto','{\n"src":"192.0.2.3",\n"src":"192.0.2.4"\n}','Unknown')]:
            status, body = self.request("POST", "/api/ingest", {"source":source,"text":raw,"record_mode":"auto"})
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body)["ingested"],1)
            _, body = self.request("GET", "/api/state")
            row = next(r for r in json.loads(body)["events"] if r["source"] == source)
            self.assertEqual(row["raw_text"],raw)
            self.assertEqual(row["format"],fmt)

    # Checks that unknown server routes return a 404 instead of exposing internals.
    def test_unknown_route_is_404(self):
        status, _ = self.request("GET", "/missing")
        self.assertEqual(status,404)


if __name__ == "__main__":
    unittest.main()
