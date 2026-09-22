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

        open_button.connect_clicked(move |_| {
            welcome_for_click.set_text("Button was clicked");
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
