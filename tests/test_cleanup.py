import sqlite3
import shutil
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

from scripts.remove_sample_data import clean
from traceweave.engine import Engine
from traceweave.fixtures import SAMPLES


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp_root = Path(__file__).resolve().parents[1] / "data" / "cleanup-tests"
        self.temp_root.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def workspace(self):
        folder = self.temp_root / str(uuid.uuid4())
        folder.mkdir()
        try:
            yield folder
        finally:
            if folder.resolve().parent != self.temp_root.resolve():
                raise RuntimeError("Test cleanup escaped its workspace")
            shutil.rmtree(folder)

    # Confirms cleanup removes only the exact duplicate sample and preserves a restorable archive.
    def test_exact_match_only_and_restorable_archive(self):
        with self.workspace() as folder:
            path = Path(folder) / "workspace.sqlite3"
            engine = Engine(path)
            source, raw = SAMPLES[0]
            fixture = engine.ingest(source, raw)
            engine.approve(source,fixture["fingerprint"],fixture["suggested_mapping"])
            engine.ingest(source, raw.replace(b"192.0.2.10",b"192.0.2.40"))
            engine.ingest("my-real-source",raw)
            engine.close()
            report = clean(path)
            self.assertEqual(report["removed"],1)
            self.assertEqual(report["remaining"],2)
            backup = sqlite3.connect(report["backup"])
            try:
                self.assertEqual(backup.execute("SELECT COUNT(*) FROM events").fetchone()[0],3)
            finally:
                backup.close()
            engine = Engine(path)
            self.assertEqual(len(engine.latest()),2)
            self.assertEqual(len(engine.state()["contracts"]),1)
            self.assertEqual(engine.history(fixture["id"]),[])
            engine.close()
            self.assertEqual(clean(path)["removed"],0)

    # Verifies orphaned sample-related state is stripped from a cleaned workspace.
    def test_orphan_sample_settings_are_removed(self):
        with self.workspace() as folder:
            path = Path(folder) / "workspace.sqlite3"
            engine = Engine(path)
            source, raw = SAMPLES[0]
            row = engine.ingest(source,raw)
            engine.approve(source,row["fingerprint"],row["suggested_mapping"])
            engine.close()
            clean(path)
            engine = Engine(path)
            self.assertEqual(engine.state()["contracts"],[])
            self.assertEqual(engine.state()["audit"],[])
            self.assertEqual(engine.latest(),[])
            engine.close()
