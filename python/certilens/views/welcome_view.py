"""Shown before a document is opened."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqua: E402


class WelcomeView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_vexpand(True)
        self.set_halign(Gtk.Align.CENTER)
        self.set_valign(Gtk.Align.CENTER)

        title = Gtk.Label(label="Drop a document, or click Open")
        title.add_css_class("title-1")

        subtitle = Gtk.Label(label="CertiLens will look for authentication evidence.")
        subtitle.add_css_class("dim-label")

        self.append(title)
        self.append(subtitle)
