"""Platform for Husqvarna Automower device tracker integration."""
from homeassistant.components.device_tracker import SOURCE_TYPE_GPS
from homeassistant.components.device_tracker.config_entry import TrackerEntity

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_devices):
    """Setup sensor platform."""
    session = hass.data[DOMAIN][entry.entry_id]
    async_add_devices(
        AutomowerTracker(session, idx) for idx, ent in enumerate(session.data["data"])
    )


class AutomowerTracker(TrackerEntity):
    """Defining the Device Tracker Entity."""

    def __init__(self, session, idx):
        self.session = session
        self.idx = idx
        self.mower = self.session.data["data"][self.idx]

        mower_attributes = self.__get_mower_attributes()
        self.mower_id = self.mower["id"]
        self.mower_name = mower_attributes["system"]["name"]
        self.model = mower_attributes["system"]["model"]

        self.session.register_cb(lambda _: self.async_write_ha_state())

    def __get_mower_attributes(self):
        return self.session.data["data"][self.idx]["attributes"]

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self.mower_id)},
            "name": self.mower_name,
            "manufacturer": "Husqvarna",
            "model": self.model,
        }

    @property
    def name(self):
        """Return the name of the entity."""
        return self.mower_name

    @property
    def unique_id(self):
        """Return a unique identifier for this entity."""
        return f"{self.mower_id}_dt"

    @property
    def source_type(self):
        """Return the source type, eg gps or router, of the device."""
        return SOURCE_TYPE_GPS

    @property
    def latitude(self):
        """Return latitude value of the device."""
        lat = self.__get_mower_attributes()["positions"][0]["latitude"]
        return lat

    @property
    def longitude(self):
        """Return longitude value of the device."""
        lon = self.__get_mower_attributes()["positions"][0]["longitude"]
        return lon
