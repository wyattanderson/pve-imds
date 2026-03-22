"""
EC2 IMDS conformance tests.

Verify that cloud-init's DataSourceEc2 can successfully crawl our IMDS
endpoint and parse the metadata we serve.
"""

from unittest import mock

import pytest

from cloudinit import helpers
from cloudinit.sources import DataSourceEc2 as ec2

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Platform data that makes identify_platform() return CloudNames.UNKNOWN
# (UUID does not start with "ec2", so no AWS identification).  With the
# default strict_id="warn" this is sufficient to proceed without IMDSv2.
_NON_AWS_PLATFORM_DATA = {
    "uuid": "00000000-0000-0000-0000-000000000000",
    "serial": "00000000-0000-0000-0000-000000000000",
    "asset_tag": "",
    "vendor": "",
    "product_name": "",
}


def _make_datasource(base_url: str, tmp_path) -> ec2.DataSourceEc2:
    """Return a DataSourceEc2 pointed at base_url with short timeouts."""
    distro = mock.MagicMock()
    distro.get_tmp_exec_path = str(tmp_path)
    paths = helpers.Paths({"run_dir": str(tmp_path)})
    ds = ec2.DataSourceEc2(sys_cfg={}, distro=distro, paths=paths)

    # Redirect all metadata requests to our local harness server.
    ds.metadata_urls = [base_url]

    # Shorten timeouts so test failures are reported quickly rather than
    # waiting the full 240-second production default.
    ds.url_max_wait = 15
    ds.url_timeout = 3

    return ds


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ds(imds_server, tmp_path):
    """DataSourceEc2 instance wired to the conformance harness."""
    return _make_datasource(imds_server["base_url"], tmp_path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEc2Conformance:
    """End-to-end conformance: DataSourceEc2 against our IMDS handler."""

    def _run_get_data(self, ds: ec2.DataSourceEc2):
        """Run _get_data() with platform detection bypassed."""
        with mock.patch(
            "cloudinit.sources.DataSourceEc2._collect_platform_data",
            return_value=_NON_AWS_PLATFORM_DATA,
        ):
            return ds._get_data()

    # ------------------------------------------------------------------
    # Service availability
    # ------------------------------------------------------------------

    def test_get_data_returns_true(self, ds):
        """_get_data() must return True — service reachable, metadata parsed."""
        result = self._run_get_data(ds)
        assert result is True, (
            "DataSourceEc2._get_data() returned False — either the server was "
            "unreachable or crawl_metadata() returned an empty dict."
        )

    # ------------------------------------------------------------------
    # Core metadata fields
    # ------------------------------------------------------------------

    def test_instance_id(self, ds, imds_server):
        """instance-id must be the Proxmox VMID as a decimal string."""
        self._run_get_data(ds)
        assert ds.metadata is not None, "metadata is None after _get_data()"
        expected = str(imds_server["vmid"])
        assert ds.metadata.get("instance-id") == expected, (
            f"Expected instance-id={expected!r}, "
            f"got {ds.metadata.get('instance-id')!r}"
        )

    def test_local_hostname(self, ds, imds_server):
        """local-hostname must be the VM name."""
        self._run_get_data(ds)
        assert ds.metadata is not None
        expected = imds_server["vm_name"]
        assert ds.metadata.get("local-hostname") == expected, (
            f"Expected local-hostname={expected!r}, "
            f"got {ds.metadata.get('local-hostname')!r}"
        )

    def test_instance_type(self, ds):
        """instance-type must be present."""
        self._run_get_data(ds)
        assert ds.metadata is not None
        assert "instance-type" in ds.metadata, (
            "instance-type missing from metadata"
        )

    def test_placement_availability_zone(self, ds, imds_server):
        """placement/availability-zone must contain the node name."""
        self._run_get_data(ds)
        assert ds.metadata is not None
        az = (
            ds.metadata.get("placement", {}).get("availability-zone", "")
            if isinstance(ds.metadata.get("placement"), dict)
            else ds.metadata.get("availability-zone", "")
        )
        assert imds_server["node"] in az, (
            f"Expected node name {imds_server['node']!r} in "
            f"availability-zone={az!r}"
        )

    # ------------------------------------------------------------------
    # User-data
    # ------------------------------------------------------------------

    def test_userdata_is_bytes_or_none(self, ds):
        """userdata_raw must be bytes or None after a successful crawl."""
        self._run_get_data(ds)
        assert ds.userdata_raw is None or isinstance(
            ds.userdata_raw, bytes
        ), f"userdata_raw has unexpected type: {type(ds.userdata_raw)}"

    # ------------------------------------------------------------------
    # get_instance_id() convenience method
    # ------------------------------------------------------------------

    def test_get_instance_id(self, ds, imds_server):
        """DataSource.get_instance_id() must return the Proxmox VMID."""
        self._run_get_data(ds)
        expected = str(imds_server["vmid"])
        assert ds.get_instance_id() == expected, (
            f"get_instance_id() returned {ds.get_instance_id()!r}, "
            f"expected {expected!r}"
        )
