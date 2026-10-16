"""A switch is ON when the MAC is not blocked by the router."""

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_DEVICES, DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    devices = entry.options.get(CONF_DEVICES, entry.data.get(CONF_DEVICES, {}))
    async_add_entities(AcerInternetSwitch(entry.runtime_data, entry, mac, name) for mac, name in devices.items())


class AcerInternetSwitch(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "internet_access"
    _attr_icon = "mdi:web"

    def __init__(self, coordinator, entry, mac, name):
        super().__init__(coordinator)
        self._mac = mac
        self._attr_unique_id = f"{entry.unique_id}_{mac}_internet"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry.unique_id}_{mac}")},
            name=name,
        )

    @property
    def available(self):
        return super().available and self.coordinator.data is not None and self._mac in self.coordinator.data.devices

    @property
    def is_on(self):
        device = self.coordinator.data.devices.get(self._mac) if self.coordinator.data else None
        return not device.blocked if device else None

    async def async_turn_on(self, **kwargs):
        await self.coordinator.async_set_blocked(self._mac, False)

    async def async_turn_off(self, **kwargs):
        await self.coordinator.async_set_blocked(self._mac, True)
