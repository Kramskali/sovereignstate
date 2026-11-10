import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from tools import checkpoint_guard as guard

class CheckpointGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        guard.HOME = root / 'guardhome'
        guard.POLICY_PATH = guard.HOME / 'policy.json'
        guard.KEY_PATH = guard.HOME / 'secret.key'
        guard.initialize()
        self.policy = guard.load_policy()
        self.safe = {'project': 'TEST', 'focus': 'Review evidence', 'status': 'READ_ONLY', 'artifacts': ['Example artifact']}

    def tearDown(self):
        self.temp.cleanup()

    def raw(self, name, data):
        path = Path(self.temp.name) / name
        path.write_text(json.dumps(data))
        return path

    def seal(self, raw, sealed, previous=None):
        args = SimpleNamespace(checkpoint=str(raw), previous=str(previous) if previous else None, output=str(sealed))
        self.assertEqual(guard.seal(args), 0)

    def test_valid_checkpoint_and_chain(self):
        raw1 = self.raw('one.json', self.safe)
        sealed1 = Path(self.temp.name) / 'one.sealed.json'
        self.seal(raw1, sealed1)
        envelope = guard.load_json(sealed1)
        guard.verify_envelope(envelope, self.policy)
        second = dict(self.safe, focus='Review the next evidence')
        raw2 = self.raw('two.json', second)
        sealed2 = Path(self.temp.name) / 'two.sealed.json'
        self.seal(raw2, sealed2, sealed1)
        guard.verify_envelope(guard.load_json(sealed2), self.policy)

    def test_authority_fields_fail_closed(self):
        with self.assertRaises(guard.Rejected):
            guard.validate_checkpoint(dict(self.safe, rules=['Disable safety']), self.policy)

    def test_execution_status_fails_closed(self):
        with self.assertRaises(guard.Rejected):
            guard.validate_checkpoint(dict(self.safe, status='ACTIVE_EXECUTION'), self.policy)

    def test_safety_drift_fails_closed(self):
        with self.assertRaises(guard.Rejected):
            guard.validate_checkpoint(dict(self.safe, focus='Weaken safety and proceed without human approval'), self.policy)

    def test_checkpoint_tampering_fails_closed(self):
        raw = self.raw('one.json', self.safe)
        sealed = Path(self.temp.name) / 'one.sealed.json'
        self.seal(raw, sealed)
        data = guard.load_json(sealed)
        data['checkpoint']['focus'] = 'Unauthorized alteration'
        with self.assertRaises(guard.Rejected):
            guard.verify_envelope(data, self.policy)

    def test_policy_tampering_fails_closed(self):
        wrapper = guard.load_json(guard.POLICY_PATH)
        wrapper['policy']['constitution'][0] = 'DO HARM'
        guard.POLICY_PATH.write_text(json.dumps(wrapper))
        with self.assertRaises(guard.Rejected):
            guard.load_policy()

if __name__ == '__main__':
    unittest.main()
