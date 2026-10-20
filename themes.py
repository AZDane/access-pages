"""Shared, allowlisted appearance for admin and guest HTML shells."""

import os


THEMES = {
    "midnight": "#08152e",
    "aurora": "#081f24",
    "ember": "#261713",
    "amethyst": "#1c1530",
    "daylight": "#f1f5fa",
}
DEFAULT_THEME = "midnight"


def render_theme(html: str) -> str:
    # Never interpolate an arbitrary environment value into HTML.
    theme = os.getenv("ACCESS_PAGES_THEME", DEFAULT_THEME)
    if theme not in THEMES:
        theme = DEFAULT_THEME
    return html.replace(
        '<html lang="en"',
        f'<html lang="en" data-theme="{theme}"',
        1,
    ).replace(
        '<meta name="theme-color" content="#08152e">',
        f'<meta name="theme-color" content="{THEMES[theme]}">',
        1,
    )
