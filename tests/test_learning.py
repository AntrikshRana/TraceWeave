import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from traceweave import learning
from traceweave.engine import Engine,convert

ROOT=Path(__file__).resolve().parents[1]

class LearningTests(unittest.TestCase):
    # Validates that the training evidence hashes match the actual model and dataset artifacts.
    def test_training_evidence_matches_model_and_gpu(self):
        report=json.loads((ROOT/'docs/evidence/gpu-training.json').read_text())
        self.assertEqual(report['backend'],'DirectML')
        self.assertIn('6500M',report['hardware']['name'])
        self.assertTrue(report['smoke_test']['passed'])
        self.assertEqual(report['model_sha256'],hashlib.sha256(learning.MODEL_PATH.read_bytes()).hexdigest())
        model=learning.load_model()
        self.assertEqual(model['training']['dataset_sha256'],hashlib.sha256((ROOT/'datasets/model/field_labels.json').read_bytes()).hexdigest())

    # Confirms AI-suggested fields are shown for review but remain hidden from export until approved.
    def test_unseen_fields_suggested_but_not_exported_without_review(self):
        engine=Engine()
        try:
            row=engine.ingest('new-device',b'sourceHostIP=192.0.2.1 destinationHostIP=198.51.100.2 traffic_verdict=deny')
            self.assertTrue(row['ai_suggestions'])
            self.assertEqual(row['suggested_mapping']['sourceHostIP'],'src_ip')
            self.assertEqual(row['status'],'needs_mapping')
            self.assertEqual(engine.export(),[])
            engine.approve(row['source'],row['fingerprint'],row['suggested_mapping'])
            self.assertEqual(len(engine.export()),1)
        finally: engine.close()

    # Makes sure alias and ambiguity logic do not overwrite existing canonical mappings.
    def test_aliases_and_ambiguous_candidates_are_not_overwritten(self):
        additions,_=learning.propose({'sourceHostIP':'192.0.2.1','clientNetworkAddress':'192.0.2.2'}, {}, convert)
        self.assertNotIn('src_ip',additions.values())
        additions,_=learning.propose({'sourceHostIP':'192.0.2.1'}, {'src':'src_ip'}, convert)
        self.assertEqual(additions,{})

    # Verifies invalid values and model failures fail safely without producing bad mappings.
    def test_invalid_values_and_model_failure_remain_safe(self):
        additions,_=learning.propose({'sourceHostIP':'not-an-address','destinationTransportPort':99999},{},convert)
        self.assertEqual(additions,{})
        with patch('traceweave.learning.load_model',side_effect=ValueError('bad model')):
            self.assertEqual(learning.propose({'sourceHostIP':'192.0.2.1'},{},convert),({},[]))

    # Confirms vendor-specific parsing takes precedence and never falls through to the AI model.
    def test_vendor_profiles_do_not_call_model(self):
        with patch('traceweave.engine.propose',side_effect=AssertionError('vendor semantics must win')):
            engine=Engine()
            try:
                row=engine.ingest('sensor',b'{"flow_id":1,"event_type":"alert","src_ip":"192.0.2.1","dest_ip":"198.51.100.2","alert":{"action":"allowed"}}')
                self.assertNotIn('action',row['canonical'])
            finally: engine.close()

    # Ensures no field label is duplicated across train, validation, and test splits.
    def test_no_normalized_field_overlap_between_splits(self):
        data=json.loads((ROOT/'datasets/model/field_labels.json').read_text())
        sets={split:{learning.normalized_name(r['field']) for r in data['rows'] if r['split']==split} for split in ('train','validation','test')}
        self.assertFalse(sets['train']&sets['test'])
        self.assertFalse(sets['train']&sets['validation'])
        self.assertFalse(sets['validation']&sets['test'])
