"""Utilitarios vulneraveis."""

import random
import string
import subprocess
import tempfile


def run_backup(directory):
    cmd = f"tar -czf /tmp/backup.tgz {directory}"
    subprocess.call(cmd, shell=True)  # EXPECT: CWE-78


def generate_reset_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(16))  # EXPECT: CWE-330


def temp_report():
    path = tempfile.mktemp(suffix=".csv")  # EXPECT: CWE-377
    return path


def parse_settings(raw):
    try:
        return dict(line.split("=", 1) for line in raw.splitlines())
    except Exception:  # EXPECT: CWE-703
        pass
