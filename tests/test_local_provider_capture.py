"""Synthetic byte evidence only: no native providers or process effects."""
import hashlib
import errno
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

    def test_directory_close_attempts_each_fd_once_and_retains_first_error(self):
        directory = capture_module._Directory(self.parent)
        owned = tuple(directory.fds)
        self.assertGreater(len(owned), 1)
        original = os.close
        attempted = []
        first = OSError(errno.EIO, 'Synthetic close completed then reported failure')
        second = OSError(errno.EINTR, 'Synthetic second close error')
        def close(fd):
            self.assertEqual(directory.fds, [])
            attempted.append(fd)
            original(fd)
            if len(attempted) == 1:
                raise first
            if len(attempted) == 2:
                raise second
        with patch.object(capture_module.os, 'close', side_effect=close), self.assertRaises(OSError) as caught:
            directory.close()
        self.assertIs(caught.exception, first)
        self.assertEqual(attempted, list(reversed(owned)))
        for fd in owned:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)
        with patch.object(capture_module.os, 'close', side_effect=AssertionError('uncertain descriptor retried')):
            directory.close()

    def test_directory_constructor_failure_closes_all_ancestors_after_close_error(self):
        directory = capture_module._Directory.__new__(capture_module._Directory)
        original_open, original_close = os.open, os.close
        opened, attempted = [], []
        first = OSError(errno.EIO, 'Synthetic constructor cleanup close error')
        def open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            opened.append(fd)
            return fd
        def close(fd):
            self.assertEqual(directory.fds, [])
            attempted.append(fd)
            original_close(fd)
            if len(attempted) == 1:
                raise first
        with patch.object(capture_module.os, 'open', side_effect=open), patch.object(capture_module.os, 'close', side_effect=close), \
                self.assertRaises(OSError) as caught:
            directory.__init__(self.parent/'missing-native-directory')
        self.assertIs(caught.exception, first)
        self.assertGreater(len(opened), 1)
        self.assertEqual(attempted, list(reversed(opened)))
        self.assertEqual(directory.fds, [])
        for fd in opened:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)
        with patch.object(capture_module.os, 'close', side_effect=AssertionError('constructor descriptor retried')):
            directory.close()

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

    def test_final_raw_fence_rejects_mutation_during_later_stream_validation(self, *, schema_version="1.0"):
        sink = self.capture(schema_version=schema_version)
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

    def test_concurrent_streams_share_one_serialized_aggregate_budget(self, *, schema_version="1.0"):
        sink = self.capture(max_output_bytes=6, schema_version=schema_version)
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

    def test_version2_exact_64MiB_combined_capture_roundtrips_incrementally(self):
        maximum = 64 * 1024 * 1024
        sink = self.capture(schema_version="2.0", max_output_bytes=maximum)
        chunk = bytes(range(256)) * 256
        streams = ("stdout", "stderr", "result")
        hashes = {stream: hashlib.sha256() for stream in streams}
        sizes = dict.fromkeys(streams, 0)
        for index in range(maximum // len(chunk)):
            stream = streams[index % len(streams)]
            sink.write(stream, chunk)
            hashes[stream].update(chunk)
            sizes[stream] += len(chunk)
        receipt = sink.finalize()
        self.assertEqual(receipt["schema_version"], "2.0")
        self.assertEqual(receipt["status"], "closed")
        self.assertFalse(sink.limited)
        self.assertEqual(receipt["records"], 1026)
        self.assertEqual(read_capture(self.root), receipt)
        for stream in streams:
            reference = receipt["streams"][stream]
            self.assertEqual(reference["retained_bytes"], sizes[stream])
            self.assertEqual(reference["observed_bytes"], sizes[stream])
            self.assertEqual(reference["sha256"], hashes[stream].hexdigest())
            with (self.root / reference["path"]).open("rb") as source:
                self.assertEqual(hashlib.file_digest(source, "sha256").hexdigest(), hashes[stream].hexdigest())
        self.assertEqual(loads((self.root / "capture.json").read_bytes())["schema_version"], "2.0")
        self.assertEqual(loads(self.record(1025).read_bytes())["schema_version"], "1.0")

    def test_version2_large_aggregate_overflow_includes_owned_result(self):
        maximum = 5 * 1024 * 1024 + 3
        sink = self.capture(schema_version="2.0", max_output_bytes=maximum)
        chunk = b"x" * 65536
        for _ in range(64):
            sink.write("stdout", chunk)
        for _ in range(16):
            sink.write("stderr", chunk)
        sink.write("result", b"12345")
        self.assertTrue(sink.limited)
        receipt = sink.finalize()
        self.assertEqual(receipt["status"], "limited")
        self.assertEqual(receipt["schema_version"], "2.0")
        self.assertEqual(sum(ref["retained_bytes"] for ref in receipt["streams"].values()), maximum)
        self.assertEqual(sum(ref["observed_bytes"] for ref in receipt["streams"].values()), maximum + 2)
        self.assertEqual((self.root / "result.bin").read_bytes(), b"123")

    def test_version2_partial_close_reopens_as_evidence_without_writer_resume(self):
        sink = self.capture(schema_version="2.0", max_output_bytes=8 * 1024 * 1024)
        chunk = b"a" * 65536
        for _ in range(65):
            sink.write("stdout", chunk)
        sink.write("stderr", b"tail")
        sink.close()
        receipt = read_capture(self.root)
        self.assertEqual(receipt["schema_version"], "2.0")
        self.assertEqual(receipt["status"], "incomplete")
        self.assertFalse(receipt["observed_counts_complete"])
        self.assertEqual(receipt["streams"]["stderr"]["uncheckpointed_bytes"], 4)
        self.rejects(lambda: PrivateCapture(self.root, schema_version="2.0"))
        self.assertEqual((self.root / "stderr.bin").read_bytes(), b"tail")

    def test_capture_schema_versions_and_metadata_capacity_are_explicit(self):
        for version in (None, True, 2, 2.0, ["2.0"], {}, "2", "1.1", "3.0"):
            self.rejects(lambda: PrivateCapture(self.root, schema_version=version))
            self.assertFalse(self.root.exists())
        self.rejects(lambda: PrivateCapture(self.root, max_output_bytes=4 * 1024 * 1024 + 1))
        self.rejects(lambda: PrivateCapture(self.root, schema_version="1.0", max_output_bytes=4 * 1024 * 1024 + 1))
        self.rejects(lambda: PrivateCapture(self.root, schema_version="2.0", max_output_bytes=64 * 1024 * 1024 + 1))
        self.rejects(lambda: PrivateCapture(self.root, schema_version="2.0", max_records=131072))
        self.rejects(lambda: PrivateCapture(self.root, schema_version="2.0", max_output_bytes=True))
        sink = self.capture()
        receipt = sink.finalize()
        self.assertEqual(receipt["schema_version"], "1.0")
        config = loads((self.root / "capture.json").read_bytes())
        self.assertEqual(config["max_output_bytes"], 4194304)

    def test_reader_does_not_reinterpret_legacy_or_unknown_config_limits(self):
        sink = self.capture()
        sink.finalize()
        path = self.root / "capture.json"
        original = loads(path.read_bytes())
        config = dict(original, max_output_bytes=64 * 1024 * 1024)
        self.rewrite(path, config)
        self.rejects(lambda: read_capture(self.root))
        for version in ("3.0", True):
            self.rewrite(path, dict(original, schema_version=version))
            self.rejects(lambda: read_capture(self.root))
        # Even a valid new version cannot relabel old immutable checkpoints;
        # their config hash binds the exact original declaration.
        self.rewrite(path, dict(original, schema_version="2.0"))
        self.rejects(lambda: read_capture(self.root))

    def test_version2_retains_final_raw_race_fence(self):
        self.test_final_raw_fence_rejects_mutation_during_later_stream_validation(schema_version="2.0")

    def test_version2_serializes_the_combined_budget(self):
        self.test_concurrent_streams_share_one_serialized_aggregate_budget(schema_version="2.0")

    def test_iter_records_requires_open_finalized_sink_and_bounded_arguments(self):
        sink = self.capture(schema_version="2.0")
        self.rejects(lambda: sink.iter_records("stdout"))
        sink.write("stdout", b"line\n")
        sink.finalize()
        for stream in (None, True, "other", "../stdout"):
            self.rejects(lambda: sink.iter_records(stream))
        for maximum in (0, -1, True, 1.0, 16 * 1024 * 1024 + 1):
            self.rejects(lambda: sink.iter_records("stdout", max_record_bytes=maximum))
        self.assertEqual(list(sink.iter_records("stdout")), [b"line"])
        iterator = sink.iter_records("stdout")
        sink.close()
        self.rejects(lambda: next(iterator))
        self.rejects(lambda: sink.iter_records("stdout"))

    def test_iter_records_preserves_blank_lines_and_requires_last_lf(self):
        sink = self.capture()
        sink.write("stdout", b"\none\n\ntwo\n")
        sink.write("stderr", b"truncated")
        sink.finalize()
        self.assertEqual(list(sink.iter_records("stdout")), [b"", b"one", b"", b"two"])
        self.assertEqual(list(sink.iter_records("result")), [])
        self.rejects(lambda: list(sink.iter_records("stderr")))
        self.rejects(lambda: list(sink.iter_records("stdout", max_record_bytes=2)))

    def test_iter_records_exact_16MiB_frame_uses_bounded_pread_windows(self):
        maximum = 16 * 1024 * 1024
        sink = self.capture(schema_version="2.0", max_output_bytes=64 * 1024 * 1024)
        chunk = b"x" * 65536
        for _ in range(maximum // len(chunk)):
            sink.write("stdout", chunk)
        sink.write("stdout", b"\nlast\n")
        sink.finalize()
        real_pread = os.pread
        requested = []
        def bounded(fd, count, offset):
            requested.append(count)
            self.assertLessEqual(count, 65536)
            return real_pread(fd, count, offset)
        position = os.lseek(sink._fds["stdout"], 0, os.SEEK_CUR)
        with patch("taskalong.local_provider_capture.os.pread", side_effect=bounded):
            iterator = sink.iter_records("stdout", max_record_bytes=maximum)
            first = next(iterator)
            self.assertEqual(len(first), maximum)
            expected_hash = hashlib.sha256()
            for _ in range(256):
                expected_hash.update(chunk)
            self.assertEqual(hashlib.sha256(first).hexdigest(), expected_hash.hexdigest())
            del first
            self.assertEqual(next(iterator), b"last")
            with self.assertRaises(StopIteration):
                next(iterator)
        self.assertTrue(requested)
        self.assertEqual(os.lseek(sink._fds["stdout"], 0, os.SEEK_CUR), position)

    def test_iter_records_hash_verification_is_required_at_exhaustion(self):
        sink = self.capture()
        sink.write("stdout", b"good\n")
        sink.finalize()
        real_pread = os.pread
        def corrupted_read(fd, count, offset):
            return real_pread(fd, count, offset).replace(b"good", b"evil")
        with patch("taskalong.local_provider_capture.os.pread", side_effect=corrupted_read):
            iterator = sink.iter_records("stdout")
            self.assertEqual(next(iterator), b"evil")
            self.rejects(lambda: next(iterator))

    def test_iter_records_rejects_tamper_between_yields(self):
        sink = self.capture(schema_version="2.0")
        sink.write("stdout", b"first\nsecond\n")
        sink.finalize()
        iterator = sink.iter_records("stdout")
        self.assertEqual(next(iterator), b"first")
        (self.root / "stdout.bin").write_bytes(b"first\nEVIL!!\n")
        self.rejects(lambda: next(iterator))

    def test_iter_records_concurrent_close_between_yields_cannot_verify(self):
        sink = self.capture(schema_version="2.0")
        sink.write("stdout", b"first\nsecond\n")
        sink.finalize()
        iterator = sink.iter_records("stdout")
        self.assertEqual(next(iterator), b"first")
        closed = threading.Event()
        def close():
            sink.close()
            closed.set()
        closer = threading.Thread(target=close)
        closer.start()
        closer.join(5)
        self.assertTrue(closed.is_set())
        self.assertFalse(closer.is_alive())
        self.rejects(lambda: next(iterator))

    def test_iter_records_rejects_hardlink_and_replaced_inode(self):
        sink = self.capture(schema_version="2.0")
        sink.write("stdout", b"first\nsecond\n")
        sink.finalize()
        iterator = sink.iter_records("stdout")
        self.assertEqual(next(iterator), b"first")
        raw = self.root / "stdout.bin"
        alias = self.parent / "linked-raw"
        os.link(raw, alias)
        self.rejects(lambda: next(iterator))
        alias.unlink()
        raw.rename(self.parent / "original-raw")
        raw.write_bytes(b"first\nsecond\n")
        raw.chmod(0o600)
        self.rejects(lambda: list(sink.iter_records("stdout")))

    def test_iter_records_rejects_link_mode_and_other_stream_changes(self):
        sink = self.capture(schema_version="2.0")
        sink.write("stdout", b"first\n")
        sink.finalize()
        iterator = sink.iter_records("stdout")
        self.assertEqual(next(iterator), b"first")
        (self.root / "stderr.bin").write_bytes(b"changed")
        self.rejects(lambda: next(iterator))
        (self.root / "stdout.bin").chmod(0o644)
        self.rejects(lambda: list(sink.iter_records("stdout")))

    def finalized_line_iterator(self):
        sink = self.capture(schema_version="2.0")
        sink.write("stdout", b"line\n")
        receipt = sink.finalize()
        iterator = sink.iter_records("stdout")
        self.assertEqual(next(iterator), b"line")
        return sink, receipt, iterator

    def test_iter_records_rejects_deleted_final_checkpoint_before_exhaustion(self):
        sink, receipt, iterator = self.finalized_line_iterator()
        self.record(receipt["records"] - 1).unlink()
        self.assertEqual(read_capture(self.root)["status"], "incomplete")
        self.rejects(lambda: list(iterator))

    def test_iter_records_rejects_checkpoint_or_config_replacement_with_identical_bytes(self):
        for name in ("capture.json", "record-000001.json"):
            with self.subTest(name=name):
                self.root = self.parent / ("replace-" + name)
                sink, receipt, iterator = self.finalized_line_iterator()
                path = self.root / name
                data = path.read_bytes()
                path.rename(self.parent / ("old-" + name))
                path.write_bytes(data)
                path.chmod(0o400)
                # Content closure alone is unchanged; immutable identity must
                # also stay bound to the metadata read at finalize.
                self.assertEqual(read_capture(self.root), receipt)
                self.rejects(lambda: list(iterator))

    def test_iter_records_rejects_mutated_config_or_final_record(self):
        for name in ("capture.json", "record-000001.json"):
            with self.subTest(name=name):
                self.root = self.parent / ("mutate-" + name)
                sink, receipt, iterator = self.finalized_line_iterator()
                path = self.root / name
                document = loads(path.read_bytes())
                if name == "capture.json":
                    document["max_records"] -= 1
                else:
                    document["finalized"] = False
                self.rewrite(path, document)
                self.rejects(lambda: list(iterator))

    def test_iter_records_rejects_metadata_symlink_or_missing_config(self):
        for operation in ("symlink", "delete"):
            with self.subTest(operation=operation):
                self.root = self.parent / operation
                sink, receipt, iterator = self.finalized_line_iterator()
                if operation == "delete":
                    (self.root / "capture.json").unlink()
                else:
                    path = self.record(receipt["records"] - 1)
                    target = self.parent / "external-index"
                    path.rename(target)
                    path.symlink_to(target)
                self.rejects(lambda: list(iterator))

    def test_returned_closure_mutation_cannot_change_iterator_expectation(self):
        sink, receipt, iterator = self.finalized_line_iterator()
        receipt["status"] = "caller-mutated"
        receipt["records"] = 0
        receipt["streams"]["stdout"]["sha256"] = "0" * 64
        self.assertEqual(list(iterator), [])
        # A caller cannot weaken the privately stored closure into an incomplete
        # one that would make deletion of the final checkpoint acceptable.
        iterator = sink.iter_records("stdout")
        self.assertEqual(next(iterator), b"line")
        self.record(1).unlink()
        receipt.clear()
        receipt.update(read_capture(self.root))
        self.rejects(lambda: list(iterator))

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
