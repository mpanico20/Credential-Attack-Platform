"""Browser fingerprint fed into seleniumbase CDP Chrome().

Two independent identities are combined into one coherent profile:

  * OS/device identity - user agent, platform, viewport. The OS is aligned to
    the REAL host OS: spoofing a different OS is a bot tell, because Web Workers
    read the real OS and a spoofed navigator.platform then mismatches the worker
    value (hasInconsistentWorkerValues). Only the viewport rotates freely - it is
    worker-safe (workers can't read window/screen).
  * Locale identity - language, timezone, geolocation. This must AGREE with the
    proxy's exit country, otherwise it becomes a bot tell (proxy in Germany but
    browser reporting Europe/Rome). It's taken from evasion.locale_profiles
    based on the proxy country, not chosen at random.

Rotating attributes independently and at random is counterproductive: what
fingerprinting services flag is inconsistency, so we rotate coherent bundles.
"""
from __future__ import annotations

import platform as _sys_platform
import random
from dataclasses import dataclass

from evasion.locale_profiles import resolve
from evasion.webgl_spoof import random_gpu

_OS_PROFILES = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Win32",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "MacIntel",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Linux x86_64",
    ),
]

_HOST_PLATFORM = {
    "Windows": "Win32",
    "Darwin": "MacIntel",
    "Linux": "Linux x86_64",
}.get(_sys_platform.system(), "Win32")


def _host_os_profile() -> tuple[str, str]:
    """The (user_agent, navigator.platform) bundle matching the REAL host OS.
    Presenting the host's own OS avoids the worker-vs-main platform mismatch that
    OS spoofing causes (hasInconsistentWorkerValues)."""
    for ua, plat in _OS_PROFILES:
        if plat == _HOST_PLATFORM:
            return ua, plat
    return _OS_PROFILES[0]


_VIEWPORTS = [(1920, 1080), (1366, 768), (1536, 864), (1440, 900)]

_FALLBACK_LANGS = ["it-IT", "en-US", "en-GB", "de-DE", "fr-FR"]
_FALLBACK_TIMEZONES = ["Europe/Rome", "Europe/Paris", "Europe/Berlin", "Europe/Madrid"]


@dataclass(frozen=True)
class Fingerprint:
    tzone: str
    lang: str
    viewport: tuple[int, int]
    user_agent: str
    platform: str
    gpu_vendor: str
    gpu_renderer: str
    geoloc: tuple[float, float] | None = None
    country: str | None = None

    def as_cdp_kwargs(self) -> dict:
        kwargs = {
            "tzone": self.tzone,
            "lang": self.lang,
            "agent": self.user_agent,
            "platform": self.platform,
        }
        if self.geoloc is not None:
            kwargs["geoloc"] = self.geoloc
        return kwargs


def build_fingerprint(country: str | None = None) -> Fingerprint:
    """Coherent profile: random OS/device + locale aligned to the proxy country.
    Falls back to a random (geo-less) locale when the country is unknown."""
    user_agent, platform = _host_os_profile()
    viewport = random.choice(_VIEWPORTS)
    gpu_vendor, gpu_renderer = random_gpu(platform)

    profile = resolve(country)
    if profile is not None:
        return Fingerprint(
            tzone=profile.timezone,
            lang=profile.lang,
            viewport=viewport,
            user_agent=user_agent,
            platform=platform,
            gpu_vendor=gpu_vendor,
            gpu_renderer=gpu_renderer,
            geoloc=profile.geo,
            country=profile.country,
        )

    return Fingerprint(
        tzone=random.choice(_FALLBACK_TIMEZONES),
        lang=random.choice(_FALLBACK_LANGS),
        viewport=viewport,
        user_agent=user_agent,
        platform=platform,
        gpu_vendor=gpu_vendor,
        gpu_renderer=gpu_renderer,
        geoloc=None,
        country=None,
    )


def random_fingerprint() -> Fingerprint:
    """Backward-compatible helper: a coherent profile with no proxy country."""
    return build_fingerprint(None)
