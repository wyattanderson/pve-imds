"""
Pytest configuration for the IMDS conformance suites.

Adds ~/git/cloud-init to sys.path so DataSource* classes can be imported
without installing cloud-init as a package, and provides session-scoped
fixtures that build the Go harness binary once and start it for each
emulation target (ec2, openstack).
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
# Shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _imds_binary(tmp_path_factory):
    """Build the conformance server binary once per test session."""
    bin_dir = tmp_path_factory.mktemp("imds_bin")
    binary = str(bin_dir / "imds-conformance-server")
    subprocess.check_call(
        ["go", "build", "-o", binary, HARNESS_PKG],
        cwd=REPO_ROOT,
    )
    return binary


def _launch_server(binary, emulate):
    """Start the harness with ``-emulate emulate``; return ``(proc, info)``.

    ``info`` is the parsed ready-line JSON dict augmented with a ``base_url``
    key pointing at the local server.
    """
    proc = subprocess.Popen(
        [binary, "-emulate", emulate],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    ready_line = proc.stdout.readline()
    if not ready_line.startswith("ready "):
        proc.terminate()
        stderr = proc.stderr.read()
        raise RuntimeError(
            f"imds-conformance-server (-emulate {emulate}) did not emit a "
            f"ready line.\ngot: {ready_line!r}\nstderr: {stderr}"
        )

    info = json.loads(ready_line[len("ready "):])
    info["base_url"] = f"http://127.0.0.1:{info['port']}"
    return proc, info


def _terminate(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def imds_server(_imds_binary):
    """EC2 IMDS harness: start, yield info dict, then terminate.

    The yielded dict has the keys defined by serverInfo in main.go:
        port, vmid, node, mac, vm_name, local_ipv4, base_url
    """
    proc, info = _launch_server(_imds_binary, "ec2")
    yield info
    _terminate(proc)


@pytest.fixture(scope="session")
def openstack_imds_server(_imds_binary):
    """OpenStack IMDS harness: start, yield info dict, then terminate.

    The yielded dict has the keys defined by serverInfo in main.go:
        port, vmid, node, mac, vm_name, local_ipv4, base_url
    """
    proc, info = _launch_server(_imds_binary, "openstack")
    yield info
    _terminate(proc)
