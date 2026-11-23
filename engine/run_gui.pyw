"""Double-clickable launcher for the native desktop GUI.

Run with pythonw (no console window): opens the Tkinter app directly, with no
local server and no browser. Use the engine's own virtualenv so the attack
subprocesses it launches have the engine's dependencies available:

    pythonw run_gui.pyw

A plain `python run_gui.pyw` works too (it just also shows a console window).
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.gui import main

if __name__ == "__main__":
    main()
