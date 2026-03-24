"""
OpenStack IMDS conformance tests.

Verify that cloud-init's DataSourceOpenStack can successfully crawl our IMDS
endpoint and parse the metadata we serve.
"""

from unittest import mock

import pytest

from cloudinit import helpers
from cloudinit.sources import DataSourceOpenStack as openstack_ds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_datasource(
    base_url: str, tmp_path
) -> openstack_ds.DataSourceOpenStack:
    """Return a DataSourceOpenStack pointed at base_url with short timeouts."""
    distro = mock.MagicMock()
    distro.get_tmp_exec_path = str(tmp_path)
    distro.fallback_interface = "eth0"
    paths = helpers.Paths({"run_dir": str(tmp_path)})
    ds = openstack_ds.DataSourceOpenStack(
        sys_cfg={}, distro=distro, paths=paths
    )

    # Redirect all metadata requests to our local harness server.
    ds.ds_cfg["metadata_urls"] = [base_url]

    # Shorten timeouts so test failures are reported quickly rather than
    # waiting the full 240-second production default.
    ds.ds_cfg["max_wait"] = 15
    ds.ds_cfg["timeout"] = 3

    return ds


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ds(openstack_imds_server, tmp_path):
    """DataSourceOpenStack instance wired to the conformance harness."""
    return _make_datasource(openstack_imds_server["base_url"], tmp_path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOpenStackConformance:
    """End-to-end conformance: DataSourceOpenStack against our IMDS handler."""

    # ------------------------------------------------------------------
    # Service availability
    # ------------------------------------------------------------------

    def test_get_data_returns_true(self, ds):
        """_get_data() must return True — service reachable, metadata parsed."""
        result = ds._get_data()
        assert result is True, (
            "DataSourceOpenStack._get_data() returned False — either the "
            "server was unreachable or metadata parsing failed."
        )

    # ------------------------------------------------------------------
    # Core metadata fields
    # ------------------------------------------------------------------

    def test_instance_id(self, ds, openstack_imds_server):
        """instance-id must be the Proxmox VMID as a decimal string."""
        ds._get_data()
        assert ds.metadata is not None, "metadata is None after _get_data()"
        expected = str(openstack_imds_server["vmid"])
        assert ds.metadata.get("instance-id") == expected, (
            f"Expected instance-id={expected!r}, "
            f"got {ds.metadata.get('instance-id')!r}"
        )

    def test_local_hostname(self, ds, openstack_imds_server):
        """local-hostname must be the VM name."""
        ds._get_data()
        assert ds.metadata is not None
        expected = openstack_imds_server["vm_name"]
        assert ds.metadata.get("local-hostname") == expected, (
            f"Expected local-hostname={expected!r}, "
            f"got {ds.metadata.get('local-hostname')!r}"
        )

    def test_availability_zone(self, ds, openstack_imds_server):
        """availability_zone must contain the Proxmox node name."""
        ds._get_data()
        assert ds.metadata is not None
        az = ds.metadata.get("availability_zone", "")
        assert openstack_imds_server["node"] in az, (
            f"Expected node name {openstack_imds_server['node']!r} in "
            f"availability_zone={az!r}"
        )

    # ------------------------------------------------------------------
    # User-data
    # ------------------------------------------------------------------

    def test_userdata_is_bytes_or_none(self, ds):
        """userdata_raw must be bytes, None, or empty string after a crawl.

        DataSourceOpenStack sets userdata_raw to an empty string (not None)
        when the server returns 404 for user_data, which is cloud-init's
        documented behaviour for absent optional files.
        """
        ds._get_data()
        ud = ds.userdata_raw
        assert ud is None or isinstance(ud, bytes) or ud == "", (
            f"userdata_raw has unexpected type/value: {type(ud)} {ud!r}"
        )

    # ------------------------------------------------------------------
    # Network data
    # ------------------------------------------------------------------

    def test_network_json_populated(self, ds):
        """network_json must be a dict with at least one link after crawl."""
        ds._get_data()
        from cloudinit.sources import UNSET

        assert ds.network_json is not UNSET, "network_json was never populated"
        assert ds.network_json is not None, "network_json is None"
        links = ds.network_json.get("links", [])
        assert len(links) >= 1, (
            f"Expected at least one link in network_json, got: {links!r}"
        )

    def test_network_config_contains_mac(self, ds, openstack_imds_server):
        """network_config must reference the VM's MAC address.

        convert_net_json() normally resolves MACs to interface names by
        inspecting the running system.  We mock that lookup to return the
        conformance VM's MAC so the test works outside a real VM.
        """
        ds._get_data()
        mac = openstack_imds_server["mac"]
        with mock.patch(
            "cloudinit.net.get_interfaces_by_mac",
            return_value={mac: "eth0"},
        ):
            net_cfg = ds.network_config
        assert net_cfg is not None, "network_config is None"
        assert mac in str(net_cfg), (
            f"Expected MAC {mac!r} somewhere in network_config:\n{net_cfg}"
        )

    # ------------------------------------------------------------------
    # get_instance_id() convenience method
    # ------------------------------------------------------------------

    def test_get_instance_id(self, ds, openstack_imds_server):
        """DataSource.get_instance_id() must return the Proxmox VMID."""
        ds._get_data()
        expected = str(openstack_imds_server["vmid"])
        assert ds.get_instance_id() == expected, (
            f"get_instance_id() returned {ds.get_instance_id()!r}, "
            f"expected {expected!r}"
        )
