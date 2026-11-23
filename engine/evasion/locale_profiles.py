"""Binds a proxy's exit country to a coherent locale profile (language,
timezone, geolocation), so the browser fingerprint agrees with the proxy IP.

The rationale: an anti-bot / fingerprinting service flags *inconsistency* -
a proxy exiting in Germany while the browser reports Europe/Rome and it-IT is
a strong tell. With Bright Data ISP proxies the exit country is something we
choose (via the zone or the username's `-country-xx` parameter), so we know it
up front and can align lang / timezone / geo to it.

Note on granularity: timezone/geo here are country-level (a representative
major city). For countries spanning multiple timezones (e.g. US) this is an
approximation; if you target a Bright Data city, extend this with city-level
entries for better accuracy.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LocaleProfile:
    country: str
    lang: str
    timezone: str
    geo: tuple[float, float]


_PROFILES: dict[str, LocaleProfile] = {
    "de": LocaleProfile("de", "de-DE", "Europe/Berlin", (52.5200, 13.4050)),
    "it": LocaleProfile("it", "it-IT", "Europe/Rome", (41.9028, 12.4964)),
    "fr": LocaleProfile("fr", "fr-FR", "Europe/Paris", (48.8566, 2.3522)),
    "es": LocaleProfile("es", "es-ES", "Europe/Madrid", (40.4168, -3.7038)),
    "gb": LocaleProfile("gb", "en-GB", "Europe/London", (51.5074, -0.1278)),
    "uk": LocaleProfile("uk", "en-GB", "Europe/London", (51.5074, -0.1278)),
    "us": LocaleProfile("us", "en-US", "America/New_York", (40.7128, -74.0060)),
    "nl": LocaleProfile("nl", "nl-NL", "Europe/Amsterdam", (52.3676, 4.9041)),
    "pl": LocaleProfile("pl", "pl-PL", "Europe/Warsaw", (52.2297, 21.0122)),
    "pt": LocaleProfile("pt", "pt-PT", "Europe/Lisbon", (38.7223, -9.1393)),
}


def resolve(country: str | None) -> LocaleProfile | None:
    """Returns the locale profile for an ISO country code, or None if unknown."""
    if not country:
        return None
    return _PROFILES.get(country.strip().lower())


def supported_countries() -> list[str]:
    return sorted(_PROFILES.keys())
