"""Shared presentation constants; no application state or I/O."""

BG = "#f4f6fa"
INK = "#17243d"
MUTED = "#718096"
BLUE = "#2563eb"


def readable_size(value):
    return f"{value / 1024 ** 3:.1f} GB"
