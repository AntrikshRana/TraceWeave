import json
import unittest
import urllib.error
from unittest.mock import Mock

from traceweave.cloud import CloudExport, NoRedirect
from traceweave.engine import Engine


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(use_model=False)
        self.cloud = CloudExport(self.engine, {"TRACEWEAVE_CLOUD_ENABLED":"1", "SUPABASE_URL":"https://abcdefghijklmnopqrst.supabase.co", "SUPABASE_SECRET_KEY":"sb_secret_unit_test_only"})
        self.response = Mock(status=201)
        self.response.__enter__ = Mock(return_value=self.response)
        self.response.__exit__ = Mock(return_value=False)
        self.cloud.opener.open = Mock(return_value=self.response)

    def tearDown(self):
        self.engine.close()

    def reviewed(self):
        row = self.engine.ingest('firewall', b'src=192.0.2.1 dst=198.51.100.2 action=deny\r\n')
        self.engine.approve(row['source'],row['fingerprint'],row['suggested_mapping'])
        return row

    # Requires explicit raw consent and blocks exports for unreviewed or malformed records.
    def test_explicit_raw_consent_and_no_unreviewed_export(self):
        self.engine.ingest('unreviewed', b'src=192.0.2.1 dst=198.51.100.2 action=deny')
        self.engine.ingest('broken', b'not a supported record')
        self.assertEqual(self.cloud.sync(True), {'sent':0,'remaining':0})
        self.cloud.opener.open.assert_not_called()
        self.reviewed()
        for consent in (False, None, 'true', 1):
            with self.assertRaises(ValueError): self.cloud.sync(consent)

    # Confirms successful sync includes the proper payload and retries only when a new revision exists.
    def test_success_retry_and_new_revision(self):
        row = self.reviewed()
        self.assertEqual(self.cloud.sync(True), {'sent':1,'remaining':0})
        request = self.cloud.opener.open.call_args.args[0]
        sent = json.loads(request.data)
        self.assertEqual(sent[0]['payload']['raw_text'],row['raw_text'])
        self.assertEqual(sent[0]['payload']['raw_base64'],row['raw_base64'])
        self.assertEqual(sent[0]['payload']['status'],'normalized')
        self.assertIn('resolution=ignore-duplicates',request.headers['Prefer'])
        self.assertNotIn('Authorization',request.headers)
        self.assertEqual(self.cloud.sync(True)['sent'],0)
        self.engine.approve(row['source'],row['fingerprint'],row['suggested_mapping'])
        self.assertEqual(self.cloud.sync(True)['sent'],1)
        self.assertEqual(self.cloud.opener.open.call_count,2)

    # Ensures network failures leave receipts unchanged and never expose the secret key in errors.
    def test_failed_network_does_not_advance_receipts_or_leak_key(self):
        self.reviewed()
        self.cloud.opener.open.side_effect = urllib.error.URLError('sb_secret_unit_test_only')
        with self.assertRaises(ValueError) as caught: self.cloud.sync(True)
        self.assertNotIn('sb_secret_',str(caught.exception))
        self.assertEqual(len(self.cloud.pending()),1)
        self.assertEqual(self.engine.db.execute('SELECT COUNT(*) FROM cloud_receipts').fetchone()[0],0)

    # Verifies disabled or invalid cloud destinations fail closed without leaking configuration data.
    def test_disabled_config_and_destination_are_fail_closed(self):
        self.reviewed()
        for url in ('http://abcdefghijklmnopqrst.supabase.co','https://evil.example','https://abcdefghijklmnopqrst.supabase.co.evil.example'):
            cloud = CloudExport(self.engine,{'TRACEWEAVE_CLOUD_ENABLED':'1','SUPABASE_URL':url,'SUPABASE_SECRET_KEY':'sb_secret_unit_test_only'})
            self.assertFalse(cloud.status()['configured'])
            with self.assertRaises(ValueError): cloud.check()
        disabled = CloudExport(self.engine,{})
        self.assertFalse(disabled.status()['configured'])
        with self.assertRaises(ValueError): disabled.sync(True)
        self.assertNotIn('sb_secret_',json.dumps(self.cloud.status()))

    # Confirms cloud receipts survive a restart and are tracked per destination workspace.
    def test_receipts_survive_object_restart_and_are_destination_scoped(self):
        self.reviewed(); self.cloud.sync(True)
        same = CloudExport(self.engine,self.cloud.config)
        self.assertEqual(same.workspace_id,self.cloud.workspace_id)
        self.assertEqual(same.pending(),[])
        other = CloudExport(self.engine,{**self.cloud.config,'SUPABASE_URL':'https://zyxwvutsrqponmlkjihg.supabase.co'})
        self.assertEqual(len(other.pending()),1)

    # Checks batch sizing limits and rejects redirect-based destination hijacking.
    def test_batch_is_bounded_and_redirect_is_refused(self):
        self.reviewed()
        for _ in range(100): self.engine.ingest('firewall',b'src=192.0.2.1 dst=198.51.100.2 action=deny\r\n')
        self.assertEqual(self.cloud.sync(True),{'sent':100,'remaining':1})
        self.assertLess(len(self.cloud.opener.open.call_args.args[0].data),1500000)
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'Moved',{},'https://evil.example'))

    # Makes sure a raw-byte integrity mismatch aborts export before any send occurs.
    def test_byte_integrity_failure_stops_send(self):
        self.reviewed()
        original_export = self.engine.export
        self.engine.export = lambda: [{**r,'raw_sha256':'0'*64} for r in original_export()]
        with self.assertRaises(ValueError): self.cloud.sync(True)
        self.cloud.opener.open.assert_not_called()
