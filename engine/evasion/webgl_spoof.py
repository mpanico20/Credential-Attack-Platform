"""WebGL GPU spoofing for CDP sessions.

Overrides WebGLRenderingContext.getParameter (and WebGL2) so that the
UNMASKED_VENDOR_WEBGL (37445) and UNMASKED_RENDERER_WEBGL (37446) parameters
report a chosen GPU instead of the host's real one. The override is injected
via the CDP command Page.addScriptToEvaluateOnNewDocument, so it runs *before*
the page's own scripts on every navigation - which is what lets it beat a
detection script that reads the GPU on page load.

IMPORTANT (found the hard way): Page.enable() must be sent BEFORE
addScriptToEvaluateOnNewDocument, otherwise the init script is registered but
never actually runs on new documents.

Honest scope note: this spoofs the reported *strings*, not the actual rendered
WebGL/canvas image hash. A full-fidelity fingerprinter that hashes the render
output can still tell GPUs apart. String spoofing defeats the common case and,
more usefully, hides the headless "Google SwiftShader" / software-renderer
tell - which is the signal that matters against the lab's defenses.
"""
from __future__ import annotations

import json
import random

import mycdp

GPU_PROFILES: dict[str, list[tuple[str, str]]] = {
    "Win32": [
        ("Google Inc. (NVIDIA)",
         "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)",
         "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)",
         "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ],
    "MacIntel": [
        ("Google Inc. (Apple)",
         "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"),
        ("Google Inc. (Apple)",
         "ANGLE (Apple, ANGLE Metal Renderer: Apple M2 Pro, Unspecified Version)"),
    ],
    "Linux x86_64": [
        ("Google Inc. (Intel)",
         "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6 "
         "(Core Profile) Mesa 22.0.5)"),
        ("Google Inc. (AMD)",
         "ANGLE (AMD, AMD Radeon RX 6600 (navi23, LLVM 15.0.7, DRM 3.49), "
         "OpenGL 4.6 (Core Profile) Mesa 23.0.4)"),
    ],
}


def random_gpu(platform: str) -> tuple[str, str]:
    """A (vendor, renderer) pair coherent with the given navigator.platform.
    Falls back to the Windows pool for an unrecognized platform."""
    pool = GPU_PROFILES.get(platform, GPU_PROFILES["Win32"])
    return random.choice(pool)


_TEMPLATE = """
const __V = %s, __R = %s;
(function() {
  function patch(proto) {
    if (!proto || !proto.getParameter) return;
    const orig = proto.getParameter;
    const patched = function(p) {
      if (p === 37445) return __V;   // UNMASKED_VENDOR_WEBGL
      if (p === 37446) return __R;   // UNMASKED_RENDERER_WEBGL
      return orig.apply(this, arguments);
    };
    // Make the override look native, so reading getParameter.toString()
    // is not itself a tell.
    patched.toString = function() { return "function getParameter() { [native code] }"; };
    proto.getParameter = patched;
  }
  patch(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
  patch(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
})();
"""


def build_script(vendor: str, renderer: str) -> str:
    return _TEMPLATE % (json.dumps(vendor), json.dumps(renderer))


def inject(driver, vendor: str, renderer: str) -> None:
    """Register the GPU spoof on a live sb_cdp driver, for all future documents.
    Must be called before navigating to the target page."""
    script = build_script(vendor, renderer)
    loop = driver.loop
    loop.run_until_complete(driver.page.send(mycdp.page.enable()))
    loop.run_until_complete(
        driver.page.send(mycdp.page.add_script_to_evaluate_on_new_document(source=script))
    )
