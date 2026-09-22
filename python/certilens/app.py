"""GTK4 application bootstrap.

Loads the CertiLens stylesheet at startup.
"""

import sys
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gtk  # noqa: E402

from .windows.main_window import MainWindow

_HERE = Path(__file__).resolve().parent
_CSS_PATH = _HERE / "resources" / "styles" / "certilens.css"


def _load_css() -> None:
    if not _CSS_PATH.exists():
        return
    provider = Gtk.CssProvider()
    provider.load_from_path(str(_CSS_PATH))
    display = Gdk.Display.get_default()
    if display is not None:
        Gtk.StyleContext.add_provider_for_display(
            display,
            provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
        )


class CertiLensApp(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(application_id="io.certilens.CertiLens")

    def do_activate(self) -> None:
        # Load the stylesheet once the app is activated.
        _load_css()

        window = self.props.active_window
        if window is None:
            window = MainWindow(application=self)
        window.present()


def run(argv: list[str]) -> int:
    app = CertiLensApp()
    return app.run(argv)
