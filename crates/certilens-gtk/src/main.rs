use adw::gio;
use adw::gtk;
use adw::prelude::*;
use certilens_core::VerificationResult;
use libadwaita as adw;
use std::sync::Once;

/// The stylesheet, embedded at compile time.
const CERTILENS_CSS: &str = include_str!("../resources/styles/certilens.css");

/// Ensure the CSS provider is loaded exactly once.
static CSS_LOADED: Once = Once::new();

fn load_css() {
    CSS_LOADED.call_once(|| {
        let provider = gtk::CssProvider::new();
        provider.load_from_string(CERTILENS_CSS);
        if let Some(display) = gtk::gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });
}

/// The initial "drop a document" placeholder.
fn build_welcome_widget() -> gtk::Widget {
    let welcome = gtk::Label::builder()
        .label("Drop a document, or click Open")
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    welcome.set_vexpand(true);
    welcome.set_valign(gtk::Align::Center);
    welcome.set_halign(gtk::Align::Center);
    welcome.upcast()
}

/// A single-verdict card: colored border, headline, subtitle, issues.
fn build_verdict_widget(verdict: &VerificationResult) -> gtk::Widget {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 6);
    outer.set_halign(gtk::Align::Fill);
    outer.set_valign(gtk::Align::Start);
    outer.add_css_class("verdict-banner");
    outer.add_css_class(verdict.severity_class());

    let headline = gtk::Label::builder()
        .label(&verdict.headline)
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .wrap(true)
        .build();
    headline.add_css_class("verdict-headline");
    outer.append(&headline);

    if !verdict.subtitle.is_empty() {
        let subtitle = gtk::Label::builder()
            .label(&verdict.subtitle)
            .halign(gtk::Align::Start)
            .xalign(0.0)
            .wrap(true)
            .build();
        subtitle.add_css_class("verdict-subtitle");
        outer.append(&subtitle);
    }

    if !verdict.issues.is_empty() {
        let sep = gtk::Separator::new(gtk::Orientation::Horizontal);
        sep.set_margin_top(8);
        sep.set_margin_bottom(4);
        outer.append(&sep);

        for issue in &verdict.issues {
            let row = gtk::Label::builder()
                .label(format!("•  {issue}"))
                .halign(gtk::Align::Start)
                .xalign(0.0)
                .wrap(true)
                .build();
            row.add_css_class("verdict-subtitle");
            outer.append(&row);
        }
    }

    outer.upcast()
}

fn main() -> adw::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("io.github.arnab-atra.Certilens")
        .build();

    app.connect_activate(|app| {
        load_css();

        // 1. Window
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("CertiLens")
            .default_width(1100)
            .default_height(700)
            .build();

        // 2. ToolbarView
        let toolbar_view = adw::ToolbarView::new();

        // 3. HeaderBar
        let header = adw::HeaderBar::new();
        toolbar_view.add_top_bar(&header);

        // 4. Content area — holds welcome OR verdict
        let content_area = adw::Bin::new();
        let welcome = build_welcome_widget();
        content_area.set_child(Some(&welcome));
        toolbar_view.set_content(Some(&content_area));

        // 5. Clones for closures
        let content_area_for_click = content_area.clone();
        let window_for_dialog = window.clone();

        // 6. Open button + click handler
        let open_button = gtk::Button::builder().label("Open").build();
        open_button.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::new();
            dialog.set_title("Open a document");

            let content_area_for_result = content_area_for_click.clone();

            dialog.open(
                Some(&window_for_dialog),
                None::<&gio::Cancellable>,
                move |result| match result {
                    Ok(file) => {
                        if let Some(path) = file.path() {
                            println!("Selected: {}", path.display());
                            println!("Running verification...");

                            match certilens_verify::assess(&path) {
                                Ok(verdict) => {
                                    println!("Verdict: {}", verdict.headline);
                                    println!("Subtitle: {}", verdict.subtitle);
                                    if verdict.issues.is_empty() {
                                        println!("  (no issues)");
                                    } else {
                                        for issue in &verdict.issues {
                                            println!("  • {issue}");
                                        }
                                    }
                                    println!();

                                    let widget = build_verdict_widget(&verdict);
                                    content_area_for_result.set_child(Some(&widget));
                                }
                                Err(err) => {
                                    println!("Assessment failed: {err}");
                                    let label = gtk::Label::builder()
                                        .label(format!("Assessment failed:\n{err}"))
                                        .wrap(true)
                                        .justify(gtk::Justification::Center)
                                        .build();
                                    label.set_vexpand(true);
                                    label.set_valign(gtk::Align::Center);
                                    label.set_halign(gtk::Align::Center);
                                    content_area_for_result.set_child(Some(&label));
                                }
                            }
                        } else {
                            println!("Non-file resource selected");
                        }
                    }
                    Err(err) => {
                        println!("Cancelled: {err}");
                    }
                },
            );
        });
        header.pack_start(&open_button);

        // 7. Attach to window
        window.set_content(Some(&toolbar_view));

        // 8. Show
        window.present();
    });

    app.run()
}
