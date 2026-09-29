import base64
import json
import uuid
import unittest
from pathlib import Path

from traceweave.engine import Engine, parse_record, normalize, suggest
from traceweave.fixtures import SAMPLES, DRIFT, ADVERSARIAL


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def tearDown(self):
        self.engine.close()

    def enroll(self, sample=SAMPLES[0]):
        row = self.engine.ingest(*sample)
        self.engine.approve(row["source"], row["fingerprint"], row["suggested_mapping"])
        return self.engine.latest()[-1]

    # Verifies that every documented sample format normalizes correctly after an approval.
    def test_all_documented_formats_normalize_after_review(self):
        for sample in SAMPLES:
            with self.subTest(source=sample[0]):
                row = self.enroll(sample)
                self.assertEqual(row["status"], "normalized")
                self.assertIn(row["canonical"]["action"], ("allow", "deny"))

    # Ensures uploaded records never auto-approve without a human mapping decision.
    def test_upload_never_auto_approves(self):
        row = self.engine.ingest(*SAMPLES[0])
        self.assertEqual(row["status"], "needs_mapping")
        self.assertEqual(self.engine.export(), [])

    # Confirms raw byte preservation keeps CRLF and spacing intact for later verification.
    def test_raw_bytes_preserve_crlf_and_whitespace(self):
        raw = b'  src=192.0.2.1 dst=198.51.100.1 action=deny  \r\n'
        row = self.engine.ingest("test", raw)
        self.assertEqual(base64.b64decode(row["raw_base64"]), raw)
        self.assertEqual(self.engine.verify()["verified"], 1)

    # Checks that duplicate JSON keys are quarantined with a clear validation error.
    def test_duplicate_json_key_quarantined(self):
        row = self.engine.ingest(*ADVERSARIAL[0])
        self.assertEqual(row["status"], "quarantined")
        self.assertIn("Duplicate field", row["errors"][0])

    # Rejects duplicate key-value fields before they can contaminate the normalized data.
    def test_duplicate_kv_field_rejected(self):
        with self.assertRaises(ValueError):
            parse_record(b"src=192.0.2.1 src=198.51.100.1")

    # Verifies binary input is retained exactly and marked as quarantined rather than discarded.
    def test_binary_input_retained(self):
        row = self.engine.ingest(*ADVERSARIAL[-1])
        self.assertEqual(row["status"], "quarantined")
        self.assertEqual(base64.b64decode(row["raw_base64"]), ADVERSARIAL[-1][1])

    # Ensures invalid ports prevent a record from ever reaching the export stream.
    def test_invalid_port_cannot_reach_export(self):
        self.enroll()
        row = self.engine.ingest(*ADVERSARIAL[1])
        self.assertEqual(row["status"], "quarantined")
        self.assertNotIn(row["id"], [r["id"] for r in self.engine.export()])

    # Confirms unknown actions are rejected and never exported as valid normalized events.
    def test_unknown_action_cannot_reach_export(self):
        self.enroll()
        row = self.engine.ingest(*ADVERSARIAL[2])
        self.assertEqual(row["status"], "quarantined")

    # Verifies drift review replays keep the original revision history intact.
    def test_drift_review_replay_keeps_old_revision(self):
        self.enroll()
        rows = [self.engine.ingest(*sample) for sample in DRIFT]
        self.assertTrue(all(r["status"] == "drift" for r in rows))
        mapping = {**rows[0]["suggested_mapping"], "origin": "src_ip"}
        result = self.engine.approve(rows[0]["source"], rows[0]["fingerprint"], mapping)
        self.assertEqual(result["normalized"], 2)
        history = self.engine.history(rows[0]["id"])
        self.assertEqual([r["status"] for r in history], ["drift", "normalized"])
        self.assertEqual(history[0]["raw_sha256"], history[1]["raw_sha256"])

    # Checks that a same-shaped but unknown action still fails even when the fingerprint matches.
    def test_same_shape_unknown_action_still_rejected(self):
        first = self.enroll()
        bad = self.engine.ingest(*ADVERSARIAL[2])
        self.assertEqual(first["fingerprint"], bad["fingerprint"])
        self.assertEqual(bad["status"], "quarantined")

    # Confirms unmapped nested fields are retained with the correct JSON pointer lineage.
    def test_unmapped_nested_content_retained(self):
        row = self.enroll(SAMPLES[2])
        self.assertEqual(row["unmapped"]["/vendor/rule"], "DNS")
        self.assertEqual(row["lineage"]["src_ip"]["selector"], "/src_ip")

    # Ensures JSON pointer escaping prevents collisions between dotted and slash-based field names.
    def test_json_pointer_no_path_collision(self):
        _, fields = parse_record(b'{"a.b":1,"a":{"b":2},"a/b":3}')
        self.assertEqual(fields, {"/a.b": 1, "/a/b": 2, "/a~1b": 3})

    # Verifies the parser does not guess a timezone when one is absent from the original value.
    def test_no_timezone_guess(self):
        fields = {"src":"192.0.2.1", "dst":"198.51.100.1", "action":"deny", "timestamp":"2026-09-19T12:00:00"}
        _, _, _, errors = normalize(fields, suggest(fields))
        self.assertTrue(any("timezone" in e for e in errors))

    # Rejects boolean values when a numeric port field is expected.
    def test_boolean_is_not_a_port(self):
        _, _, _, errors = normalize({"dpt":True}, {"dpt":"dst_port"})
        self.assertTrue(any("unsupported value type" in e for e in errors))

    # Prevents a mapping from assigning two fields to the same output target.
    def test_mapping_rejects_duplicate_targets(self):
        row = self.engine.ingest(*SAMPLES[0])
        with self.assertRaises(ValueError):
            self.engine.approve(row["source"], row["fingerprint"], {"src":"src_ip", "dst":"src_ip"})

    # Bars mappings that silently invent unsupported destination fields.
    def test_mapping_cannot_silently_invent_a_field(self):
        row = self.engine.ingest(*SAMPLES[0])
        with self.assertRaises(ValueError):
            self.engine.approve(row["source"], row["fingerprint"], {"imaginary":"src_ip", "dst":"dst_ip", "action":"action"})

    # Verifies source-specific contracts stay isolated from one another.
    def test_source_contract_isolation(self):
        self.enroll()
        other = self.engine.ingest("other-source", SAMPLES[0][1])
        self.assertEqual(other["status"], "needs_mapping")

    # Ensures rollback restores the prior contract and reprocesses the data correctly.
    def test_rollback_reprocesses_with_previous_contract(self):
        row = self.enroll()
        mapping = dict(row["suggested_mapping"])
        mapping.pop("spt")
        self.engine.approve(row["source"], row["fingerprint"], mapping)
        self.assertNotIn("src_port", self.engine.latest()[0]["canonical"])
        self.engine.rollback(row["source"], row["fingerprint"])
        self.assertEqual(self.engine.latest()[0]["canonical"]["src_port"], 51432)

    # Detects tampering by verifying the stored evidence against the original raw input.
    def test_evidence_corruption_detected(self):
        row = self.enroll()
        self.engine.db.execute("UPDATE events SET raw=? WHERE id=?", (b"altered", row["id"]))
        self.assertEqual(self.engine.verify()["failed"], [row["id"]])
        updated = self.engine.process(row["id"])
        self.assertEqual(updated["status"], "quarantined")

    # Confirms database records persist across engine instances and remain verifiable after reopen.
    def test_database_persistence(self):
        folder = Path(__file__).resolve().parents[1] / "data"
        folder.mkdir(exist_ok=True)
        path = folder / ("test-" + uuid.uuid4().hex + ".sqlite3")
        try:
            one = Engine(path)
            row = one.ingest(*SAMPLES[0])
            one.approve(row["source"], row["fingerprint"], row["suggested_mapping"])
            one.close()
            two = Engine(path)
            self.assertEqual(two.latest()[0]["status"], "normalized")
            self.assertEqual(two.verify()["verified"], 1)
            two.close()
        finally:
            if path.exists():
                path.unlink()

    # Ensures XML entity expansion is not evaluated during record ingestion.
    def test_xml_entities_not_evaluated(self):
        row = self.engine.ingest("xml", b'<!DOCTYPE x [<!ENTITY a "b">]><x><src>&a;</src></x>')
        self.assertEqual(row["status"], "quarantined")

    # Rejects unquoted values that are ambiguous and cannot be parsed safely.
    def test_unquoted_ambiguous_values_rejected(self):
        with self.assertRaises(ValueError):
            parse_record(b'src=192.0.2.1 dst=198.51.100.1 action=deny rule=two words')

    # Confirms quoted values and escaped quotes are parsed exactly as intended.
    def test_quoted_values_and_escaped_quotes(self):
        _, fields = parse_record(b'src=192.0.2.1 rule="two \\"words\\""')
        self.assertEqual(fields["rule"], 'two "words"')

    # Keeps invalid records visible after contract replay instead of silently dropping them.
    def test_invalid_records_remain_after_contract_replay(self):
        self.enroll()
        self.engine.ingest(*ADVERSARIAL[1])
        row = self.engine.latest()[0]
        result = self.engine.approve(row["source"], row["fingerprint"], row["suggested_mapping"])
        self.assertEqual(result["normalized"], 1)
        self.assertEqual(self.engine.latest()[1]["status"], "quarantined")


if __name__ == "__main__":
    unittest.main()
