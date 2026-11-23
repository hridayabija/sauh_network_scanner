"""Single-device SQLite outbox: durable jobs/results, immutable retry identities."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time


def private_path(path, *, directory=False):
    path = Path(path)
    if directory:
        path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # chmod does not remove inherited Windows ACLs. Grant the current user
        # and SYSTEM on a device-local directory; never silently leave it public.
        import csv

        who = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            check=True,
        )
        sid = next(csv.reader(who.stdout.splitlines()))[1]
        permission = f"*{sid}:(OI)(CI)F" if directory else f"*{sid}:F"
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", permission],
            capture_output=True,
            check=True,
        )
    else:
        path.chmod(0o700 if directory else 0o600)


class DeviceLock:
    def __init__(self, path):
        self.path, self.file = Path(path), None

    def __enter__(self):
        self.file = self.path.open("a+b")
        self.file.seek(0)
        self.file.write(b"0")
        self.file.flush()
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise ValueError("A scanner already owns this state directory") from None
        return self

    def __exit__(self, *args):
        if os.name == "nt":
            import msvcrt

            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        self.file.close()


class Outbox:
    def __init__(self, directory):
        self.directory = Path(directory)
        private_path(self.directory, directory=True)
        self.path = self.directory / "outbox.sqlite3"
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, kind TEXT, phase TEXT, state TEXT, payload TEXT);
        CREATE TABLE IF NOT EXISTS results(id TEXT PRIMARY KEY, assignment_id TEXT, attempt INTEGER,
            payload TEXT, hash TEXT, UNIQUE(assignment_id, attempt));
        CREATE TABLE IF NOT EXISTS claims(lane TEXT PRIMARY KEY, payload TEXT);
        CREATE TABLE IF NOT EXISTS logs(id TEXT PRIMARY KEY, payload TEXT);
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT);
        CREATE INDEX IF NOT EXISTS ix_results_job ON results(assignment_id);
        """)
        private_path(self.path)
        # A crashed running job is not restarted with the same attempt/identity.
        with self.db:
            self.db.execute("UPDATE jobs SET state='abandoned' WHERE state='running'")

    def count(self):
        return self.db.execute("SELECT count(*) FROM results").fetchone()[0]

    def bytes(self):
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        free = self.db.execute("PRAGMA freelist_count").fetchone()[0]
        size = self.db.execute("PRAGMA page_size").fetchone()[0]
        wal = self.path.with_name(self.path.name + "-wal")
        return (pages - free) * size + (wal.stat().st_size if wal.exists() else 0)

    def claim_request(self, lane, payload):
        row = self.db.execute(
            "SELECT payload FROM claims WHERE lane=?", (lane,)
        ).fetchone()
        if row:
            return json.loads(row[0])
        with self.db:
            self.db.execute(
                "INSERT INTO claims VALUES(?,?)", (lane, json.dumps(payload))
            )
        return payload

    def receive_jobs(self, lane, jobs):
        with self.db:
            for job in jobs:
                self.db.execute(
                    "INSERT OR IGNORE INTO jobs VALUES(?,?,?,?,?)",
                    (
                        job["id"],
                        job["kind"],
                        job["check_kind"],
                        "pending",
                        json.dumps(job),
                    ),
                )
            self.db.execute("DELETE FROM claims WHERE lane=?", (lane,))

    def take_jobs(self, kind, phase, count):
        rows = self.db.execute(
            "SELECT id,payload FROM jobs WHERE kind=? AND phase=? AND state='pending' LIMIT ?",
            (kind, phase, count),
        ).fetchall()
        with self.db:
            self.db.executemany(
                "UPDATE jobs SET state='running' WHERE id=?",
                [(row["id"],) for row in rows],
            )
        return [json.loads(row["payload"]) for row in rows]

    def finish_job(self, identity):
        with self.db:
            self.db.execute("UPDATE jobs SET state='done' WHERE id=?", (identity,))
            self.db.execute(
                "DELETE FROM jobs WHERE id=? AND NOT EXISTS "
                "(SELECT 1 FROM results WHERE results.assignment_id=jobs.id)",
                (identity,),
            )

    def save_result(self, job, observation):
        payload = dict(assignment_id=job["id"], observation=observation)
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(text.encode()).hexdigest()
        previous = self.db.execute(
            "SELECT hash FROM results WHERE id=?", (observation["id"],)
        ).fetchone()
        if previous and previous[0] != digest:
            raise ValueError("A saved observation is immutable")
        attempt = self.db.execute(
            "SELECT id FROM results WHERE assignment_id=? AND attempt=?",
            (job["id"], observation["attempt_count"]),
        ).fetchone()
        if attempt and attempt[0] != observation["id"]:
            raise ValueError("A saved attempt cannot be replaced by another identity")
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO results VALUES(?,?,?,?,?)",
                (
                    observation["id"],
                    job["id"],
                    observation["attempt_count"],
                    text,
                    digest,
                ),
            )

    def results(self, limit):
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT payload FROM results ORDER BY rowid LIMIT ?", (limit,)
            )
        ]

    def acknowledge(self, identities):
        with self.db:
            self.db.executemany(
                "DELETE FROM results WHERE id=?",
                [(identity,) for identity in identities],
            )
            self.db.execute(
                "DELETE FROM jobs WHERE state IN ('done','abandoned') AND NOT EXISTS "
                "(SELECT 1 FROM results WHERE results.assignment_id=jobs.id)"
            )
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def log(self, entry):
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO logs VALUES(?,?)",
                (entry["id"], json.dumps(entry)),
            )
            self.db.execute(
                "DELETE FROM logs WHERE rowid NOT IN (SELECT rowid FROM logs ORDER BY rowid DESC LIMIT 1000)"
            )

    def logs(self, limit=50):
        return [
            json.loads(row[0])
            for row in self.db.execute(
                "SELECT payload FROM logs ORDER BY rowid LIMIT ?", (limit,)
            )
        ]

    def acknowledge_logs(self, identities):
        with self.db:
            self.db.executemany(
                "DELETE FROM logs WHERE id=?", [(identity,) for identity in identities]
            )

    def close(self):
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.close()
