"""Synthetic byte evidence only: no native providers or process effects."""
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from taskalong.errors import TaskAlongError
from taskalong import local_provider_capture as capture_module
from taskalong.local_provider_capture import PrivateCapture, read_capture
from taskalong.validation import canonical_bytes, loads


class PrivateCaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        self.root = self.parent / "capture"

    def capture(self, **options):
        result = PrivateCapture(self.root, **options)
        self.addCleanup(result.close)
        return result

    def rejects(self, operation):
        with self.assertRaises(TaskAlongError):
            operation()

    def record(self, index):
        return self.root / f"record-{index:06d}.json"

    def rewrite(self, path, document):
        path.chmod(0o600)
        path.write_bytes(canonical_bytes(document))
        path.chmod(0o400)

    def test_interleaved_combined_overflow_preserves_allowed_prefix(self):
        sink = self.capture(max_output_bytes=7)
        sink.write("stdout", b"ab")
        sink.write("stderr", b"cde")
        sink.write("stdout", b"fghij")
        sink.write("stderr", b"k")
        self.assertTrue(sink.limited)
        receipt = sink.finalize()
        self.assertEqual(receipt["status"], "limited")
        self.assertTrue(receipt["byte_closure"])
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"abfg")
        self.assertEqual((self.root / "stderr.bin").read_bytes(), b"cde")
        self.assertEqual(receipt["streams"]["stdout"]["observed_bytes"], 7)
        self.assertEqual(receipt["streams"]["stderr"]["observed_bytes"], 4)
        self.assertEqual(sum(s["actual_bytes"] for s in receipt["streams"].values()), 7)
        self.assertTrue(receipt["observed_counts_complete"])

    def test_exact_cap_and_final_receipt_match_raw_hashes(self):
        sink = self.capture(max_output_bytes=4)
        sink.write("stdout", b"\xff\0")
        sink.write("stderr", b"\n!")
        receipt = sink.finalize()
        self.assertEqual(receipt, read_capture(self.root))
        self.assertEqual(receipt["status"], "closed")
        self.assertFalse(sink.limited)
        for stream, ref in receipt["streams"].items():
            data = (self.root / ref["path"]).read_bytes()
            self.assertEqual(ref["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(ref["actual_bytes"], ref["checkpointed_bytes"])
            self.assertEqual(ref["uncheckpointed_bytes"], 0)
            self.assertEqual(stat.S_IMODE((self.root / ref["path"]).stat().st_mode), 0o600)
        self.rejects(lambda: sink.write("stdout", b"later"))
        self.rejects(sink.finalize)

    def test_result_bytes_share_same_cap(self):
        sink = self.capture(max_output_bytes=5)
        sink.write("result", b"1234")
        sink.write("stdout", b"56")
        sink.write("result", b"78")
        receipt = sink.finalize()
        self.assertEqual((self.root / "result.bin").read_bytes(), b"1234")
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"5")
        self.assertEqual(receipt["streams"]["result"]["observed_bytes"], 6)
        self.assertTrue(receipt["output_limited"])

    def test_closed_partial_evidence_and_crashlike_tail_are_honest(self):
        sink = self.capture()
        sink.write("stdout", b"checkpoint")
        sink.checkpoint()
        sink.write("stderr", b"uncheckpointed")
        sink.close()
        first = read_capture(self.root)
        self.assertEqual(first["status"], "incomplete")
        self.assertFalse(first["byte_closure"])
        self.assertFalse(first["observed_counts_complete"])
        self.assertEqual(first["streams"]["stdout"]["checkpointed_bytes"], 10)
        self.assertEqual(first["streams"]["stderr"]["uncheckpointed_bytes"], 14)
        self.assertEqual(first["streams"]["stderr"]["observed_bytes"], 0)
        with (self.root / "stdout.bin").open("ab") as output:
            output.write(b"tail")
        second = read_capture(self.root)
        self.assertEqual(second["streams"]["stdout"]["uncheckpointed_bytes"], 4)
        self.assertEqual((self.root / "stderr.bin").read_bytes(), b"uncheckpointed")
        self.rejects(lambda: PrivateCapture(self.root))

    def test_raw_checkpoint_cadence_is_bounded_not_per_write(self):
        sink = self.capture()
        for _ in range(100):
            sink.write("stdout", b"x")
        self.assertEqual(len(list(self.root.glob("record-*"))), 1)
        sink.write("stderr", b"z" * (65_536 * 3))
        self.assertEqual(len(list(self.root.glob("record-*"))), 4)
        self.assertEqual(read_capture(self.root)["streams"]["stderr"]["uncheckpointed_bytes"], 100)
        sink.finalize()

    def test_metadata_is_bounded_independently_and_final_slot_reserved(self):
        sink = self.capture(max_records=3)
        for i in range(30):
            sink.observe({"sequence": i})
        sink.observe({"oversized": "a" * 5000})
        receipt = sink.finalize()
        self.assertEqual(receipt["records"], 3)
        self.assertEqual(receipt["observations"], {"observed": 31, "retained": 4})
        self.assertTrue(receipt["metadata_limited"])
        self.assertEqual(receipt["status"], "limited")
        self.assertTrue(all(p.stat().st_size <= 16_384 for p in self.root.glob("*.json")))

    def test_observe_preserves_strict_unknown_event_without_usage_claims(self):
        sink = self.capture()
        event = {"provider_specific": {"unknown": [True, None, 17]}}
        sink.observe(event)
        event["provider_specific"]["unknown"].append("mutated")
        sink.finalize()
        latest = loads(self.record(1).read_bytes())
        self.assertEqual(latest["events"], [{"provider_specific": {"unknown": [True, None, 17]}}])
        self.assertNotIn("usage", read_capture(self.root))

    def test_malformed_params_streams_chunks_and_events(self):
        for options in ({"max_output_bytes": True}, {"max_output_bytes": -1},
                        {"max_output_bytes": 4_194_305}, {"max_records": True},
                        {"max_records": 1}, {"max_records": 8193}):
            self.rejects(lambda: PrivateCapture(self.root, **options))
        sink = self.capture(max_output_bytes=0)
        for stream in ("other", "stdout.bin", "../stdout", True, None):
            self.rejects(lambda: sink.write(stream, b"x"))
        for chunk in ("text", bytearray(b"x"), None):
            self.rejects(lambda: sink.write("stdout", chunk))
        self.rejects(lambda: sink.observe({"float": 1.0}))
        self.rejects(lambda: sink.observe({1: "key"}))
        self.rejects(lambda: sink.observe([]))
        sink.write("stdout", b"x")
        self.assertEqual(sink.finalize()["status"], "limited")

    def test_unsafe_fresh_paths_and_existing_artifacts_are_rejected(self):
        target = self.parent / "real"
        target.mkdir(mode=0o700)
        self.root.symlink_to(target, target_is_directory=True)
        self.rejects(lambda: PrivateCapture(self.root))
        self.root.unlink()
        linked_parent = self.parent / "linked"
        linked_parent.symlink_to(target, target_is_directory=True)
        self.rejects(lambda: PrivateCapture(linked_parent / "capture"))
        self.root.mkdir(mode=0o700)
        marker = self.root / "capture.json"
        marker.write_bytes(b"old")
        self.rejects(lambda: PrivateCapture(self.root))
        self.assertEqual(marker.read_bytes(), b"old")
        self.rejects(lambda: PrivateCapture(self.parent / "x" / ".." / "escaped"))

    def test_prefix_tamper_rejects_even_when_size_matches(self):
        sink = self.capture()
        sink.write("stdout", b"private")
        sink.finalize()
        (self.root / "stdout.bin").write_bytes(b"changed")
        self.rejects(lambda: read_capture(self.root))

    def test_links_and_replaced_control_files_reject(self):
        sink = self.capture()
        sink.finalize()
        raw = self.root / "stdout.bin"
        hardlink = self.parent / "alias"
        os.link(raw, hardlink)
        self.rejects(lambda: read_capture(self.root))
        hardlink.unlink()
        raw.unlink()
        raw.symlink_to(self.root / "stderr.bin")
        self.rejects(lambda: read_capture(self.root))

    def test_live_inode_replacement_and_same_size_mutation_poison_sink(self):
        sink = self.capture()
        sink.write("stdout", b"one")
        raw = self.root / "stdout.bin"
        raw.rename(self.parent / "old")
        raw.write_bytes(b"one")
        raw.chmod(0o600)
        self.rejects(lambda: sink.write("stdout", b"two"))
        self.rejects(sink.finalize)
        self.assertEqual(raw.read_bytes(), b"one")

    def test_live_same_inode_mutation_is_fenced(self):
        sink = self.capture()
        sink.write("stdout", b"one")
        (self.root / "stdout.bin").write_bytes(b"two")
        self.rejects(sink.checkpoint)
        self.rejects(sink.finalize)

    def test_record_chain_hashes_and_semantics_are_validated(self):
        sink = self.capture()
        sink.write("stdout", b"bytes")
        sink.checkpoint()
        sink.finalize()
        record = loads(self.record(1).read_bytes())
        record["metadata_limited"] = True
        self.rewrite(self.record(1), record)
        self.rejects(lambda: read_capture(self.root))

    def test_checkpoint_hash_tamper_and_torn_index_are_errors(self):
        sink = self.capture()
        sink.write("stdout", b"a")
        sink.checkpoint()
        record = loads(self.record(1).read_bytes())
        record["streams"]["stdout"]["sha256"] = "0" * 64
        self.rewrite(self.record(1), record)
        self.rejects(lambda: read_capture(self.root))
        self.record(1).chmod(0o600)
        self.record(1).write_bytes(b'{"torn":')
        self.record(1).chmod(0o400)
        self.rejects(lambda: read_capture(self.root))

    def test_unexpected_gap_or_finalized_tail_is_not_ignored(self):
        sink = self.capture()
        sink.finalize()
        with (self.root / "stdout.bin").open("ab") as handle:
            handle.write(b"late")
        self.rejects(lambda: read_capture(self.root))
        (self.root / "stdout.bin").write_bytes(b"")
        self.record(1).rename(self.record(2))
        self.rejects(lambda: read_capture(self.root))

    def test_partial_writes_are_retried_without_changing_bytes(self):
        sink = self.capture()
        real_write = os.write
        with patch("taskalong.local_provider_capture.os.write", side_effect=lambda fd, data: real_write(fd, data[:2])):
            sink.write("stdout", b"abcdefgh")
            sink.observe({"synthetic": True})
            receipt = sink.finalize()
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"abcdefgh")
        self.assertEqual(receipt["status"], "closed")

    def test_partial_raw_failure_retains_tail_and_cannot_finalize(self):
        sink = self.capture()
        real_write = os.write
        calls = 0
        def fail_after_prefix(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:2])
            raise OSError("synthetic failure")
        with patch("taskalong.local_provider_capture.os.write", side_effect=fail_after_prefix):
            self.rejects(lambda: sink.write("stdout", b"abcdef"))
        self.rejects(sink.finalize)
        sink.close()
        receipt = read_capture(self.root)
        self.assertEqual(receipt["status"], "incomplete")
        self.assertEqual(receipt["streams"]["stdout"]["uncheckpointed_bytes"], 2)
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"ab")

    def test_raw_fsync_failure_creates_no_completion_record(self):
        sink = self.capture()
        sink.write("stdout", b"pending")
        with patch("taskalong.local_provider_capture.os.fsync", side_effect=OSError("synthetic fsync")):
            self.rejects(sink.finalize)
        sink.close()
        self.assertEqual(read_capture(self.root)["status"], "incomplete")
        self.assertEqual(len(list(self.root.glob("record-*"))), 1)

    def test_partial_index_write_is_not_blindly_ignored_or_accepted(self):
        sink = self.capture()
        sink.write("stdout", b"evidence")
        real_write = os.write
        first = True
        def torn(fd, data):
            nonlocal first
            if first:
                first = False
                return real_write(fd, data[:8])
            raise OSError("synthetic torn index")
        with patch("taskalong.local_provider_capture.os.write", side_effect=torn):
            self.rejects(sink.finalize)
        sink.close()
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"evidence")
        self.assertTrue(self.record(1).exists())
        self.rejects(lambda: read_capture(self.root))

    def test_control_hardlink_and_nonprivate_file_are_rejected(self):
        sink = self.capture()
        sink.finalize()
        alias = self.parent / "linked-index"
        os.link(self.record(1), alias)
        self.rejects(lambda: read_capture(self.root))
        alias.unlink()
        self.record(1).chmod(0o444)
        self.rejects(lambda: read_capture(self.root))

    def test_interrupted_write_retries_safely(self):
        sink = self.capture()
        real_write = os.write
        first = True
        def interrupted(fd, data):
            nonlocal first
            if first:
                first = False
                raise InterruptedError()
            return real_write(fd, data)
        with patch("taskalong.local_provider_capture.os.write", side_effect=interrupted):
            sink.write("stdout", b"retry")
        self.assertEqual(sink.finalize()["status"], "closed")
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"retry")

    def test_index_numeric_bool_and_unknown_files_are_rejected(self):
        sink = self.capture()
        sink.finalize()
        original = loads(self.record(1).read_bytes())
        altered = loads(self.record(1).read_bytes())
        altered["streams"]["stdout"]["retained_bytes"] = False
        self.rewrite(self.record(1), altered)
        self.rejects(lambda: read_capture(self.root))
        self.rewrite(self.record(1), original)
        (self.root / "unknown").write_bytes(b"unaccounted")
        self.rejects(lambda: read_capture(self.root))

    def test_final_raw_fence_rejects_mutation_during_later_stream_validation(self):
        sink = self.capture()
        sink.write("stdout", b"good")
        sink.finalize()
        real_entry = capture_module._entry
        stderr_checks = 0
        def mutate_after_stdout_was_checked(directory, name, fd, maximum, mode):
            nonlocal stderr_checks
            result = real_entry(directory, name, fd, maximum, mode)
            if name == "stderr.bin":
                stderr_checks += 1
                if stderr_checks == 2:
                    (self.root / "stdout.bin").write_bytes(b"evil")
            return result
        with patch("taskalong.local_provider_capture._entry", side_effect=mutate_after_stdout_was_checked):
            self.rejects(lambda: read_capture(self.root))
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"evil")

    def test_concurrent_streams_share_one_serialized_aggregate_budget(self):
        sink = self.capture(max_output_bytes=6)
        first_writing = threading.Event()
        second_attempted = threading.Event()
        release_first = threading.Event()
        errors = []
        lock = threading.RLock()
        class ObservedLock:
            def __enter__(self):
                if threading.current_thread().name == "capture-stderr":
                    second_attempted.set()
                lock.acquire()
                return self
            def __exit__(self, *args):
                lock.release()
        sink._lock = ObservedLock()
        real_write_all, real_entry = capture_module._write_all, capture_module._entry
        def gated_write(fd, data, *args):
            if fd == sink._fds["stdout"]:
                first_writing.set()
                if not release_first.wait(5):
                    raise AssertionError("first writer was not released")
            return real_write_all(fd, data, *args)
        def entered(directory, name, fd, maximum, mode):
            # Without serialization this point is after the second writer has
            # already reserved the same six bytes as the paused first writer.
            if name == "stderr.bin" and threading.current_thread().name == "capture-stderr":
                second_attempted.set()
            return real_entry(directory, name, fd, maximum, mode)
        def write(stream, data):
            try:
                sink.write(stream, data)
            except Exception as exc:
                errors.append(exc)
        first = threading.Thread(target=write, args=("stdout", b"aaaaaa"), name="capture-stdout")
        second = threading.Thread(target=write, args=("stderr", b"bbbbbb"), name="capture-stderr")
        with patch("taskalong.local_provider_capture._write_all", side_effect=gated_write), patch("taskalong.local_provider_capture._entry", side_effect=entered):
            try:
                first.start()
                self.assertTrue(first_writing.wait(5))
                second.start()
                self.assertTrue(second_attempted.wait(5))
            finally:
                release_first.set()
                first.join(5)
                if second.ident is not None:
                    second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual((self.root / "stdout.bin").read_bytes(), b"aaaaaa")
        self.assertEqual((self.root / "stderr.bin").read_bytes(), b"")
        self.assertTrue(sink.limited)
        receipt = sink.finalize()
        self.assertEqual(receipt["status"], "limited")
        self.assertEqual(sum(s["retained_bytes"] for s in receipt["streams"].values()), 6)
        self.assertEqual(sum(s["observed_bytes"] for s in receipt["streams"].values()), 12)

    def test_raw_fsync_precedes_each_immutable_record_creation(self):
        sink = self.capture()
        sink.write("stdout", b"pending")
        events = []
        real_sync, real_open = os.fsync, os.open
        def sync(fd):
            events.append(("sync", fd))
            return real_sync(fd)
        def opening(path, flags, *args, **kwargs):
            if str(path).startswith("record-") and flags & os.O_CREAT:
                events.append(("index", path))
            return real_open(path, flags, *args, **kwargs)
        with patch("taskalong.local_provider_capture.os.fsync", side_effect=sync), patch("taskalong.local_provider_capture.os.open", side_effect=opening):
            sink.finalize()
        creation = next(i for i, event in enumerate(events) if event[0] == "index")
        self.assertTrue(set(sink._fds.values()).issubset({event[1] for event in events[:creation] if event[0] == "sync"}))


if __name__ == "__main__":
    unittest.main()
