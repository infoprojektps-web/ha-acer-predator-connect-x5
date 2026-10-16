"""Connect locally, then explicitly select controllable devices."""

try:
    import probatio as vol
except ImportError:  # Home Assistant releases before the schema migration.
    import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers import selector

from .client import AuthenticationError, RouterClient, RouterError, normalize_mac, normalize_url
from .const import CONF_DEVICES, CONF_PROTECTED_MACS, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DEFAULT_URL, DOMAIN
from .protocol import ProtocolError


def _connection_schema(default_host=DEFAULT_URL):
    return vol.Schema({
        vol.Required(CONF_HOST, default=default_host): str,
        vol.Required(CONF_PASSWORD): selector.TextSelector(selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)),
    })


def _device_schema(snapshot, selected=(), interval=DEFAULT_SCAN_INTERVAL, protected=()):
    choices = [selector.SelectOptionDict(value=mac, label=f"{device.name} ({mac})")
               for mac, device in sorted(snapshot.devices.items()) if mac not in snapshot.protected_macs]
    return vol.Schema({
        vol.Required(CONF_DEVICES, default=list(selected)): selector.SelectSelector(selector.SelectSelectorConfig(options=choices, multiple=True)),
        vol.Optional(CONF_PROTECTED_MACS, default=list(protected)): selector.SelectSelector(selector.SelectSelectorConfig(options=[selector.SelectOptionDict(value=mac, label=device.name + " (" + mac + ")") for mac, device in sorted(snapshot.devices.items())], multiple=True)),
        vol.Optional(CONF_SCAN_INTERVAL, default=interval): selector.NumberSelector(selector.NumberSelectorConfig(min=30, max=600, step=1, mode=selector.NumberSelectorMode.BOX)),
    })


def _selection(snapshot, user_input):
    selected = {normalize_mac(mac) for mac in user_input[CONF_DEVICES]}
    protected = {normalize_mac(mac) for mac in user_input.get(CONF_PROTECTED_MACS, [])} | snapshot.protected_macs
    if not selected or selected & protected or not selected <= snapshot.devices.keys():
        raise ValueError("Invalid selection")
    interval = int(user_input.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
    if not 30 <= interval <= 600:
        raise ValueError("Invalid interval")
    return {CONF_DEVICES: {mac: snapshot.devices[mac].name for mac in sorted(selected)}, CONF_PROTECTED_MACS: sorted(protected), CONF_SCAN_INTERVAL: interval}


async def _read(hass, host, password):
    client = await hass.async_add_executor_job(RouterClient, host, password)
    try:
        return await hass.async_add_executor_job(client.get_devices)
    finally:
        # Closing only clears local state. It does not log out another client.
        await hass.async_add_executor_job(client.close)


class AcerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                host = normalize_url(user_input[CONF_HOST])
                await self.async_set_unique_id(host)
                self._abort_if_unique_id_configured()
                snapshot = await _read(self.hass, host, user_input[CONF_PASSWORD])
            except ValueError:
                errors["base"] = "invalid_host"
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except (RouterError, ProtocolError):
                errors["base"] = "cannot_connect"
            else:
                self._connection = {CONF_HOST: host, CONF_PASSWORD: user_input[CONF_PASSWORD]}
                self._snapshot = snapshot
                return await self.async_step_devices()
        return self.async_show_form(step_id="user", data_schema=_connection_schema(), errors=errors)

    async def async_step_devices(self, user_input=None):
        errors = {}
        if user_input is not None:
            try:
                selection = _selection(self._snapshot, user_input)
            except ValueError:
                errors["base"] = "invalid_selection"
            else:
                return self.async_create_entry(title="Acer Predator Connect X5", data={**self._connection, **selection})
        return self.async_show_form(step_id="devices", data_schema=_device_schema(self._snapshot), errors=errors)

    async def async_step_reauth(self, entry_data):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        entry = self._get_reauth_entry()
        return await self._credentials_step(entry, "reauth_confirm", user_input)

    async def async_step_reconfigure(self, user_input=None):
        entry = self._get_reconfigure_entry()
        return await self._credentials_step(entry, "reconfigure", user_input)

    async def _credentials_step(self, entry, step, user_input):
        errors = {}
        if user_input is not None:
            try:
                host = normalize_url(user_input[CONF_HOST])
                # Moving a configured router to a new address needs a new entry.
                if host != entry.data[CONF_HOST]:
                    raise ValueError
                await _read(self.hass, host, user_input[CONF_PASSWORD])
            except ValueError:
                errors["base"] = "invalid_host"
            except AuthenticationError:
                errors["base"] = "invalid_auth"
            except (RouterError, ProtocolError):
                errors["base"] = "cannot_connect"
            else:
                return self.async_update_reload_and_abort(entry, data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD]})
        return self.async_show_form(step_id=step, data_schema=_connection_schema(entry.data[CONF_HOST]), errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return AcerOptionsFlow()


class AcerOptionsFlow(config_entries.OptionsFlow):
    async def async_step_init(self, user_input=None):
        entry = self.config_entry
        if not hasattr(self, "_snapshot"):
            try:
                self._snapshot = await _read(self.hass, entry.data[CONF_HOST], entry.data[CONF_PASSWORD])
            except (RouterError, ProtocolError):
                return self.async_abort(reason="cannot_connect")
        errors = {}
        if user_input is not None:
            try:
                selection = _selection(self._snapshot, user_input)
            except ValueError:
                errors["base"] = "invalid_selection"
            else:
                return self.async_create_entry(title="", data=selection)
        selected = entry.options.get(CONF_DEVICES, entry.data.get(CONF_DEVICES, {}))
        protected = entry.options.get(CONF_PROTECTED_MACS, entry.data.get(CONF_PROTECTED_MACS, []))
        return self.async_show_form(step_id="init", data_schema=_device_schema(self._snapshot, [mac for mac in selected if mac in self._snapshot.devices and mac not in self._snapshot.protected_macs], entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL), [mac for mac in protected if mac in self._snapshot.devices]), errors=errors)
