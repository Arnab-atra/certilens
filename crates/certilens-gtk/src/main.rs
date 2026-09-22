use adw::gio;
use adw::gtk;
use adw::prelude::*;
use libadwaita as adw;

fn main() -> adw::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("io.github.arnab-atra.Certilens")
        .build();

    app.connect_activate(|app| {
        // 1. The window
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Certilens")
            .default_width(1100)
            .default_height(700)
            .build();

        // 2. The ToolbarView - the three-region container.
        let toolbar_view = adw::ToolbarView::new();

        // 3. The header bar - put it in the ToolbarView's top slot.
        let header = adw::HeaderBar::new();
        toolbar_view.add_top_bar(&header);

        // 4. The welcome label.
        let welcome = gtk::Label::builder()
            .label("Drop a document, or click Open")
            .build();
        welcome.set_vexpand(true);
        welcome.set_valign(gtk::Align::Center);
        welcome.set_halign(gtk::Align::Center);

        // 5. Clone the label handle for the click handler.
        //    Must come BEFORE the closure that uses it.
        let welcome_for_click = welcome.clone();

        // 6. The Open button + click handler.
        let open_button = gtk::Button::builder().label("Open").build();
        // Give the click handler its own handle to the window, so it can be
        // the parent of the file dialog.
        let window_for_dialog = window.clone();

        open_button.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::new();
            dialog.set_title("Open a document");

            let welcome_for_result = welcome_for_click.clone();

            dialog.open(
                Some(&window_for_dialog),
                None::<&gio::Cancellable>,
                move |result| match result {
                    Ok(file) => {
                        if let Some(path) = file.path() {
                            println!("Selected: {}", path.display());
                            welcome_for_result.set_text(&path.display().to_string());
                        } else {
                            welcome_for_result.set_text("Selected a non-file resource");
                        }
                    }
                    Err(err) => {
                        println!("Cancelled: {err}");
                        welcome_for_result.set_text("No file selected");
                    }
                },
            );
        });

        header.pack_start(&open_button);

        // 7. Put the welcome label into the ToolbarView's content slot.
        toolbar_view.set_content(Some(&welcome));

        // 8. Attach the ToolbarView to the window as its child.
        window.set_content(Some(&toolbar_view));

        // 9. Show the window.
        window.present();
    });

    app.run()
}
