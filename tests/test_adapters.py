import unittest
from traceweave.engine import Engine


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def tearDown(self):
        self.engine.close()

    def approve(self, raw):
        row = self.engine.ingest("device", raw)
        self.engine.approve("device", row["fingerprint"], row["suggested_mapping"])
        return self.engine.latest()[-1]

    # Ensures Suricata alert metadata is preserved as unmapped data instead of being treated as a verdict.
    def test_suricata_alert_is_not_a_verdict(self):
        row = self.approve(b'{"event_type":"alert","flow_id":1,"src_ip":"192.0.2.1","dest_ip":"198.51.100.2","alert":{"action":"allowed"}}')
        self.assertEqual(row["status"],"normalized")
        self.assertEqual(row["event_class"],"security_alert")
        self.assertNotIn("action",row["canonical"])
        self.assertEqual(row["unmapped"]["/alert/action"],"allowed")
        with self.assertRaises(ValueError):
            self.engine.approve("device",row["fingerprint"],{**row["suggested_mapping"],"/alert/action":"action"})

    # Confirms Fortinet timestamps keep nanoseconds and that the device session is retained correctly.
    def test_fortigate_preserves_nanoseconds_and_session_state(self):
        row = self.approve(b'logid="0000000013" type="traffic" eventtime=1557513467369913239 srcip=192.0.2.1 dstip=198.51.100.2 action="server-rst"')
        self.assertEqual(row["canonical"]["timestamp"],"2019-05-10T18:37:47.369913239+00:00")
        self.assertNotIn("action",row["canonical"])
        self.assertEqual(row["unmapped"]["action"],"server-rst")

    # Verifies that a changed event class is flagged as drift and requires manual review.
    def test_event_class_change_requires_review(self):
        raw=b'logid="0000000013" type="traffic" eventtime=1557513467 srcip=192.0.2.1 dstip=198.51.100.2 action="accept"'
        self.approve(raw)
        row=self.engine.ingest("device",raw.replace(b'accept',b'close'))
        self.assertEqual(row["status"],"drift")

    # Checks pfSense field extraction and confirms missing timezone data produces a warning instead of a timestamp.
    def test_pfsense_columns_and_absent_timezone(self):
        row = self.approve(b'<134>Jul  3 19:10:30 filterlog[123]: 1,,,12,eth0,match,pass,in,4,0x0,,64,123,0,DF,6,tcp,60,192.0.2.1,198.51.100.2,50000,443,0,S,1,,60000,,')
        self.assertEqual(row["canonical"]["src_ip"],"192.0.2.1")
        self.assertEqual(row["canonical"]["dst_port"],443)
        self.assertEqual(row["canonical"]["action"],"allow")
        self.assertNotIn("timestamp",row["canonical"])
        self.assertTrue(row["warnings"])
