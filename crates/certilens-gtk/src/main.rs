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

        // 4. The welcome label - put it in the ToolbarView's content slot.
        let welcome = gtk::Label::builder()
            .label("Drop a document, or click Open")
            .build();
        welcome.set_vexpand(true);
        welcome.set_valign(gtk::Align::Center);
        welcome.set_halign(gtk::Align::Center);
        toolbar_view.set_content(Some(&welcome));

        // 5. Attach the ToolbarView to the window as it child.
        window.set_content(Some(&toolbar_view));

        // 6. Show the window
        window.present();
    });

    app.run()
}
