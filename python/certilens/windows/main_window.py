"""The main CertiLens window."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402
from ..views.welcome_view import WelcomeView
from ..views.verification_view import VerificationView


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, application: Gtk.Application) -> None:
        super().__init__(application=application)

        self.set_title("CertiLens")
        self.set_default_size(960, 640)

        # A vertical box stack widgets top-to-bottom.
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Header bar with an "Open" button.
        header = Gtk.HeaderBar()
        open_button = Gtk.Button(label="Open Document")
        open_button.connect("clicked", self._on_open_clicked)
        header.pack_start(open_button)
        self.set_titlebar(header)

        # The content area swap between Welcome and Verification views.
        self._verification_view = VerificationView()
        self._welcome_view = WelcomeView()

        root.append(self._welcome_view)
        self.set_child(root)

        self._root = root

    # ------------------------------------------------------------------
    # signal handlers
    # ------------------------------------------------------------------
    def _on_open_clicked(self, _button: Gtk.Button) -> None:
        """Open a native file chooser."""
        dialog = Gtk.FileDialog()
        dialog.set_title("Open a document")

        # open() is asynchronous; the callback runs later.
        dialog.open(self, None, self._on_file_chosen)

    def _on_file_chosen(self, dialog: Gtk.FileDialog, result) -> None:
        try:
            gfile = dialog.open_finish(result)
        except Exception:
            return  # user cancelled
        if gfile is None:
            return
        path = gfile.get_path()
        if path:
            self._show_verification(path)

    def _show_verification(self, path: str) -> None:
        """Swap the welcome view for the verification view."""
        self._root.remove(self._welcome_view)
        self._verification_view.load(path)
        self._root.append(self._verification_view)
