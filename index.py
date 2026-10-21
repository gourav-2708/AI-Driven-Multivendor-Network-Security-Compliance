"""
Vercel entrypoint for the net-audit web dashboard.

Vercel's Flask preset looks for an `app` object in a root-level index.py.
The application itself lives in frontends/web/app.py; this file only makes
it importable from the repository root.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontends", "web"))

from app import app  # noqa: E402  (re-exported for Vercel)

__all__ = ["app"]
