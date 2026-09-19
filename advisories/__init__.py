"""Red Queen advisory-generation package.

Renders a security "finding record" (a plain dict / JSON file) to both a
Markdown advisory and a styled PDF advisory.
"""

from .generate_advisory import render_advisory, main  # noqa: F401

__all__ = ["render_advisory", "main"]
