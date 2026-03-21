"""
Pytest configuration for the EC2 IMDS conformance suite.

Adds ~/git/cloud-init to sys.path so DataSourceEc2 can be imported without
installing cloud-init as a package, and provides the shared `imds_server`
fixture that builds and starts the Go harness binary.
"""

import json
import os
import subprocess
import sys

import pytest

# ---------------------------------------------------------------------------
# cloud-init import path
# ---------------------------------------------------------------------------

CLOUD_INIT_DIR = os.path.expanduser("~/git/cloud-init")
if CLOUD_INIT_DIR not in sys.path:
    sys.path.insert(0, CLOUD_INIT_DIR)

# ---------------------------------------------------------------------------
# Repository root
# ---------------------------------------------------------------------------

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HARNESS_PKG = "./cmd/imds-conformance-server"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def imds_server(tmp_path_factory):
    """Build the Go harness binary, start it, and yield its server info dict.

    The yielded dict has the keys defined by serverInfo in main.go:
        port, vmid, node, mac, vm_name, local_ipv4

    The process is terminated after the test session completes.
    """
    bin_dir = tmp_path_factory.mktemp("imds_bin")
    binary = str(bin_dir / "imds-conformance-server")

    subprocess.check_call(
        ["go", "build", "-o", binary, HARNESS_PKG],
        cwd=REPO_ROOT,
    )

    proc = subprocess.Popen(
        [binary],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT,
    )

    # Read the "ready {json}" line.  The binary flushes stdout immediately
    # after writing it, so this readline() should return quickly.
    ready_line = proc.stdout.readline()
    if not ready_line.startswith("ready "):
        proc.terminate()
        stderr = proc.stderr.read()
        raise RuntimeError(
            f"imds-conformance-server did not emit a ready line.\n"
            f"got: {ready_line!r}\nstderr: {stderr}"
        )

    info = json.loads(ready_line[len("ready "):])
    info["base_url"] = f"http://127.0.0.1:{info['port']}"

    yield info

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
