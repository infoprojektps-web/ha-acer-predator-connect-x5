"""Run with real Home Assistant installed; no router or credentials required."""

import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.acer_predator_connect import config_flow, switch  # noqa: E402
from custom_components.acer_predator_connect.client import Device, RouterError, Snapshot  # noqa: E402
from custom_components.acer_predator_connect.const import CONF_DEVICES, CONF_SCAN_INTERVAL  # noqa: E402

MANAGER = "02:00:00:00:00:01"
TARGET = "02:00:00:00:00:02"
snapshot = Snapshot({MANAGER: Device(MANAGER, "Manager", False, "192.0.2.10"), TARGET: Device(TARGET, "Tablet", False, "192.0.2.20")}, "192.0.2.10")
schema = config_flow._device_schema(snapshot)
validated = schema({CONF_DEVICES: [TARGET], CONF_SCAN_INTERVAL: 30})
selection = config_flow._selection(snapshot, validated)
assert selection[CONF_DEVICES] == {TARGET: "Tablet"}
assert MANAGER in selection["protected_macs"]

# Devices that go offline must remain selectable and keep their original MAC.
offline_snapshot = Snapshot(
    {MANAGER: Device(MANAGER, "Manager", False, "192.0.2.10")},
    "192.0.2.10",
)
old_devices = {TARGET: "Tablet"}
offline_schema = config_flow._device_schema(
    offline_snapshot, selected=[TARGET], selected_names=old_devices,
)
offline_values = offline_schema({CONF_DEVICES: [TARGET], CONF_SCAN_INTERVAL: 30})
retained = config_flow._selection(
    offline_snapshot, offline_values, previously_selected=old_devices,
)
assert retained[CONF_DEVICES] == old_devices
# Adding a new, invisible MAC is not allowed, even though retaining an
# already configured offline MAC is allowed.
try:
    config_flow._selection(
        offline_snapshot, {CONF_DEVICES: ["02:00:00:00:00:04"]},
        previously_selected=old_devices,
    )
except ValueError:
    pass
else:
    raise AssertionError("A new MAC that is absent from the router was accepted")
try:
    config_flow._selection(snapshot, {CONF_DEVICES: [MANAGER]})
except ValueError:
    pass
else:
    raise AssertionError("Management client selection was accepted")
config_flow._connection_schema()({"host": "http://192.0.2.1:8080", "password": "synthetic-password"})


class FakeCoordinator:
    last_update_success = True
    data = snapshot
    calls = []

    async def async_set_blocked(self, mac, blocked):
        self.calls.append((mac, blocked))


async def main():
    active = SimpleNamespace(data=snapshot, last_update_success=True, async_refresh=AsyncMock())
    options_entry = SimpleNamespace(runtime_data=active)
    with patch.object(config_flow, "RouterClient", side_effect=AssertionError("Options must not open a second session")), patch.object(config_flow, "_read", side_effect=AssertionError("Options must reuse the coordinator")):
        result = await config_flow._read_options_snapshot(options_entry)
        assert result is snapshot
        active.async_refresh.assert_awaited_once()
        active.last_update_success = False
        for failed_entry in (options_entry, SimpleNamespace()):
            try:
                await config_flow._read_options_snapshot(failed_entry)
            except RouterError:
                pass
            else:
                raise AssertionError("Options accepted unavailable data")

    coordinator = FakeCoordinator()
    entry = SimpleNamespace(unique_id="http://192.0.2.1:8080")
    entity = switch.AcerInternetSwitch(coordinator, entry, TARGET, "Tablet")
    assert entity.is_on is True
    assert entity.available is True
    await entity.async_turn_off()
    await entity.async_turn_on()
    assert coordinator.calls == [(TARGET, True), (TARGET, False)]
    coordinator.data = Snapshot({TARGET: Device(TARGET, "Tablet", True)}, "192.0.2.10")
    assert entity.is_on is False
    coordinator.data = Snapshot({}, "192.0.2.10")
    assert entity.available is False
    assert entity.is_on is None


asyncio.run(main())
manifest = json.loads((Path(__file__).resolve().parents[1] / "custom_components/acer_predator_connect/manifest.json").read_text())
assert manifest["domain"] == "acer_predator_connect"
print("Home Assistant imports, config schemas and switch smoke checks passed")
