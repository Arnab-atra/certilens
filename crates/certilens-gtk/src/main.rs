use adw::prelude::*;
use libadwaita as adw;

fn main() -> adw::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("io.github.arnab-atra.Certilens")
        .build();

    app.connect_activate(|app| {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Certilens")
            .default_width(1100)
            .default_height(700)
            .build();

        window.present();
    });

    app.run()
}
