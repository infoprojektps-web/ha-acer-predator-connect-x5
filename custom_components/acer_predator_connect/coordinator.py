"""Shared polling and verified writes."""

from datetime import timedelta
import logging

from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import AuthenticationError, RouterError, Snapshot
from .const import DOMAIN
from .protocol import ProtocolError

_LOGGER = logging.getLogger(__name__)


class AcerCoordinator(DataUpdateCoordinator[Snapshot]):
    def __init__(self, hass, entry, client, interval):
        super().__init__(hass, _LOGGER, name=DOMAIN, config_entry=entry, update_interval=timedelta(seconds=max(30, min(int(interval), 600))))
        self.client = client

    async def _async_update_data(self):
        try:
            return await self.hass.async_add_executor_job(self.client.get_devices)
        except AuthenticationError:
            raise ConfigEntryAuthFailed("Check the router password or login lockout") from None
        except (RouterError, ProtocolError) as err:
            # Client/protocol errors contain only controlled messages, never
            # response bodies, URLs, credentials or request headers.
            raise UpdateFailed(f"Router state could not be read: {err}") from None

    async def async_set_blocked(self, mac: str, blocked: bool) -> None:
        try:
            snapshot = await self.hass.async_add_executor_job(self.client.set_blocked, mac, blocked)
        except (RouterError, ProtocolError) as err:
            self.async_set_update_error(UpdateFailed(f"Router command could not be verified: {err}"))
            raise HomeAssistantError(f"Router command failed or was refused for safety: {err}; no automatic retry") from None
        self.async_set_updated_data(snapshot)
