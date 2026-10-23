"""Real SIGKILL barriers exercise persisted state; no successful store call is mocked."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import unittest

from taskalong.errors import TaskAlongError
from taskalong.store import Store
from test_store import StoreFixture

_TRANSACTION_CHILD = r'''
import os, signal, sys
from taskalong.store import Store, encode
root, run_id, barrier_fd, position = sys.argv[1:]
barrier_fd = int(barrier_fd)
with Store(root) as store:
    run = store.run(run_id)
    with store.transaction() as db:
        run['revision'] += 1
        run['state'] = 'ready'
        db.execute('UPDATE runs SET revision=?,state=?,document=? WHERE run_id=?', (run['revision'],run['state'],encode(run),run_id))
        if position == 'after-row':
            os.write(barrier_fd, b'R')
            signal.pause()
        store._event(db, run, 'run.ready')
        if position == 'after-event':
            os.write(barrier_fd, b'E')
            signal.pause()
    if position == 'after-commit':
        os.write(barrier_fd, b'C')
        signal.pause()
'''

_BLOB_CHILD = r'''
import os, signal, sys
from taskalong.store import Store
root, barrier_fd, position = sys.argv[1:]
barrier_fd = int(barrier_fd)
with Store(root) as store:
    # SQLite's trace callback is a real transaction-entry barrier. put_blob has
    # already written, fsynced and renamed the object before this BEGIN executes.
    def trace(statement):
        if statement == 'BEGIN IMMEDIATE' and position == 'after-rename':
            os.write(barrier_fd,b'B')
            signal.pause()
    store.db.set_trace_callback(trace)
    store.put_blob(b'original synthetic crash artifact')
    if position == 'after-commit':
        os.write(barrier_fd,b'C')
        signal.pause()
'''


class CrashRecoveryTests(StoreFixture):
    def kill_at_barrier(self, program, *arguments):
        reader, writer = os.pipe()
        process = subprocess.Popen([sys.executable, "-c", program, *map(str, arguments), str(writer)],
                                   pass_fds=(writer,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(writer)
        try:
            ready, _, _ = select.select([reader], [], [], 10)
            if not ready:
                process.kill()
                output, error = process.communicate(timeout=5)
                self.fail("Crash barrier was not reached: " + error.decode(errors="replace")[-1500:])
            receipt = os.read(reader, 1)
            if not receipt:
                output, error = process.communicate(timeout=5)
                self.fail("Child exited before the transaction barrier: " + error.decode(errors="replace")[-1500:])
            process.send_signal(signal.SIGKILL)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            return receipt
        finally:
            os.close(reader)
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def transaction_child(self, position):
        # The argument order keeps the inherited FD last for a portable helper.
        program = _TRANSACTION_CHILD.replace("root, run_id, barrier_fd, position = sys.argv[1:]", "root, run_id, position, barrier_fd = sys.argv[1:]")
        return self.kill_at_barrier(program, self.state, self.run["run_id"], position)

    def blob_child(self, position):
        program = _BLOB_CHILD.replace("root, barrier_fd, position = sys.argv[1:]", "root, position, barrier_fd = sys.argv[1:]")
        return self.kill_at_barrier(program, self.state, position)

    def test_kill_between_row_and_event_has_neither_after_reopen(self):
        self.assertEqual(self.transaction_child("after-row"), b"R")
        with Store(self.state) as reopened:
            self.assertEqual(reopened.run(self.run["run_id"]), self.run)
            self.assertEqual(len(reopened.events(self.run["run_id"])), 1)

    def test_kill_after_event_before_commit_has_neither_after_reopen(self):
        self.assertEqual(self.transaction_child("after-event"), b"E")
        with Store(self.state) as reopened:
            self.assertEqual(reopened.run(self.run["run_id"]), self.run)
            self.assertEqual(len(reopened.events(self.run["run_id"])), 1)

    def test_kill_after_commit_preserves_both_row_and_event(self):
        self.assertEqual(self.transaction_child("after-commit"), b"C")
        with Store(self.state) as reopened:
            observed = reopened.run(self.run["run_id"])
            events = reopened.events(self.run["run_id"])
            self.assertEqual((observed["revision"], observed["state"]), (2, "ready"))
            self.assertEqual([e["seq"] for e in events], [1, 2])
            self.assertEqual(events[-1]["run_revision"], 2)

    def test_kill_after_blob_rename_leaves_orphan_without_reference(self):
        self.assertEqual(self.blob_child("after-rename"), b"B")
        sha = hashlib.sha256(b"original synthetic crash artifact").hexdigest()
        with Store(self.state) as reopened:
            self.assertTrue((reopened.blob_root / sha).is_file())
            self.assertEqual(reopened.db.execute("SELECT count(*) FROM blobs WHERE sha256=?", (sha,)).fetchone()[0], 0)
            with self.assertRaises(TaskAlongError):
                reopened.get_blob(sha)
            self.assertEqual(reopened.run(self.run["run_id"]), self.run)

    def test_kill_after_blob_commit_preserves_integrity(self):
        self.assertEqual(self.blob_child("after-commit"), b"C")
        sha = hashlib.sha256(b"original synthetic crash artifact").hexdigest()
        with Store(self.state) as reopened:
            self.assertEqual(reopened.get_blob(sha), b"original synthetic crash artifact")


if __name__ == "__main__":
    unittest.main()
