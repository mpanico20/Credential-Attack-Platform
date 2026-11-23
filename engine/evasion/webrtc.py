"""WebRTC leak prevention.

WebRTC can reveal the browser's real public IP via STUN even when all HTTP(S)
traffic goes through a proxy: it opens its own UDP path and bypasses the proxy.
For an attack that relies on proxy rotation for anonymity, this is a serious hole -
the target (or its anti-bot) could see the true origin IP regardless of the proxy.

We fix it with a Chrome launch flag rather than by disabling the WebRTC JS API:
a browser where RTCPeerConnection is missing or broken is itself a bot tell,
whereas this keeps the API working while blocking the non-proxied leak path.

Policy `disable_non_proxied_udp`: WebRTC may only use UDP that goes through the
proxy. With a typical HTTP(S) proxy (which does not carry UDP), this suppresses
the STUN server-reflexive (srflx) candidates, so the real public IP is never
gathered. Local IPs are already hidden by Chrome's default mDNS obfuscation.
"""
from __future__ import annotations

WEBRTC_LEAK_PREVENTION_ARGS = [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
]


def webrtc_leak_prevention_args() -> list[str]:
    return list(WEBRTC_LEAK_PREVENTION_ARGS)
