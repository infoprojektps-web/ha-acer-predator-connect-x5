"""Local access-control integration for Acer Predator Connect X5."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .client import RouterClient
from .const import CONF_DEVICES, CONF_PROTECTED_MACS, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
from .coordinator import AcerCoordinator

PLATFORMS = [Platform.SWITCH]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    devices = entry.options.get(CONF_DEVICES, entry.data.get(CONF_DEVICES, {}))
    protected = entry.options.get(CONF_PROTECTED_MACS, entry.data.get(CONF_PROTECTED_MACS, []))
    if not devices:
        raise ConfigEntryNotReady("Select at least one device in integration options")
    client = await hass.async_add_executor_job(
        RouterClient, entry.data[CONF_HOST], entry.data[CONF_PASSWORD], devices, protected
    )
    coordinator = AcerCoordinator(hass, entry, client, entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await hass.async_add_executor_job(client.close)
        raise
    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await hass.async_add_executor_job(entry.runtime_data.client.close)
        return True
    return False
