"""Coherent User-Agent Client Hints for CDP sessions.

CDP mode ships with the UserAgentClientHint feature disabled, so the browser
sends a Chrome User-Agent header but NO Sec-CH-UA client-hint headers, and
navigator.userAgentData.brands is empty. A header-level detector flags this as
"UserAgent.untrusted": the UA claims Chrome, but the Client Hints a real Chrome
would send are missing.

This re-applies Network.setUserAgentOverride with a userAgentMetadata coherent
with the UA string (matching Chrome version + platform), so the User-Agent and
the Client Hints agree. Call once after launch, before navigating.

Found empirically on seleniumbase.io/antibot/login: UA override alone (even the
native UA) is flagged; UA + coherent Client Hints is not.
"""
from __future__ import annotations

import re

import mycdp

_PLATFORM_MAP = {
    "Win32": ("Windows", "10.0.0"),
    "MacIntel": ("macOS", "13.0.0"),
    "Linux x86_64": ("Linux", "6.5.0"),
}


def _chrome_version(user_agent: str) -> str:
    m = re.search(r"Chrome/([\d.]+)", user_agent)
    return m.group(1) if m else "128.0.0.0"


def build_metadata(user_agent: str, navigator_platform: str) -> "mycdp.emulation.UserAgentMetadata":
    """Client-Hints metadata coherent with the given UA string and platform."""
    full = _chrome_version(user_agent)
    major = full.split(".")[0]
    ch_platform, ch_platform_version = _PLATFORM_MAP.get(navigator_platform, ("Windows", "10.0.0"))

    def bv(brand: str, version: str) -> "mycdp.emulation.UserAgentBrandVersion":
        return mycdp.emulation.UserAgentBrandVersion(brand=brand, version=version)

    brands = [bv("Not(A:Brand", "99"), bv("Google Chrome", major), bv("Chromium", major)]
    full_version_list = [
        bv("Not(A:Brand", "99.0.0.0"),
        bv("Google Chrome", full),
        bv("Chromium", full),
    ]
    return mycdp.emulation.UserAgentMetadata(
        platform=ch_platform,
        platform_version=ch_platform_version,
        architecture="x86",
        model="",
        mobile=False,
        brands=brands,
        full_version_list=full_version_list,
        full_version=full,
        bitness="64",
        wow64=False,
    )


def inject(driver, user_agent: str, navigator_platform: str) -> None:
    """Re-apply the UA together with coherent Client Hints for the session.
    Must be called before navigating to the target page."""
    meta = build_metadata(user_agent, navigator_platform)
    loop = driver.loop
    loop.run_until_complete(
        driver.page.send(
            mycdp.network.set_user_agent_override(
                user_agent=user_agent,
                platform=navigator_platform,
                user_agent_metadata=meta,
            )
        )
    )
