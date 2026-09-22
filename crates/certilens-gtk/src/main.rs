use adw::gio;
use adw::gtk;
use adw::prelude::*;
use certilens_core::VerificationResult;
use certilens_verify::{
    Assessment, CertificateSummary, ChainSummary, CheckOutcome, SignatureReport,
};
use libadwaita as adw;
use std::sync::Once;

const CERTILENS_CSS: &str = include_str!("../resources/styles/certilens.css");
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

/// Insert thousands separators into an unsigned integer.
/// 3485794 → "3,485,794"
fn format_thousands(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

// -----------------------------------------------------------------------------
// Small widget helpers
// -----------------------------------------------------------------------------

fn section_title(text: &str) -> gtk::Label {
    let l = gtk::Label::builder()
        .label(text)
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .build();
    l.add_css_class("section-title");
    l
}

fn kv_row(key: &str, value: &str, mono: bool) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);

    let k = gtk::Label::builder()
        .label(key)
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .width_chars(16)
        .build();
    k.add_css_class("kv-key");

    let v = gtk::Label::builder()
        .label(value)
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .wrap(true)
        .selectable(true)
        .build();
    v.add_css_class(if mono { "kv-mono" } else { "kv-value" });

    row.append(&k);
    row.append(&v);
    row
}

fn inline_banner(text: &str, kind: &str) -> gtk::Label {
    let l = gtk::Label::builder()
        .label(text)
        .halign(gtk::Align::Fill)
        .xalign(0.0)
        .wrap(true)
        .build();
    l.add_css_class(if kind == "ok" {
        "inline-ok"
    } else {
        "inline-warn"
    });
    l
}

fn check_outcome_widget(outcome: &CheckOutcome) -> gtk::Widget {
    let box_ = gtk::Box::new(gtk::Orientation::Vertical, 6);

    let kind = if outcome.passed { "ok" } else { "warn" };
    let mark = if outcome.passed { "✓" } else { "✗" };
    box_.append(&inline_banner(
        &format!("{mark}  {}", outcome.summary),
        kind,
    ));

    for detail in &outcome.details {
        let d = gtk::Label::builder()
            .label(detail)
            .halign(gtk::Align::Start)
            .xalign(0.0)
            .wrap(true)
            .selectable(true)
            .build();
        d.add_css_class("kv-mono");
        box_.append(&d);
    }

    box_.upcast()
}

// -----------------------------------------------------------------------------
// Card builders
// -----------------------------------------------------------------------------

fn claims_card(report: &SignatureReport) -> gtk::Widget {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 6);
    card.add_css_class("card");

    card.append(&section_title("Claims in the PDF"));

    let mut rows: Vec<(String, String)> = Vec::new();

    if let Some(v) = &report.filter {
        rows.push(("Filter".into(), v.clone()));
    }
    if let Some(v) = &report.sub_filter {
        rows.push(("SubFilter".into(), v.clone()));
    }
    if let Some(v) = &report.claimed_signer {
        rows.push(("Claimed signer".into(), v.clone()));
    }
    if let Some(v) = &report.claimed_time {
        rows.push(("Claimed time".into(), v.clone()));
    }
    if let Some(v) = &report.reason {
        rows.push(("Reason".into(), v.clone()));
    }
    if let Some(v) = &report.location {
        rows.push(("Location".into(), v.clone()));
    }
    if let Some(br) = &report.byte_range {
        if br.len() == 4 {
            let pretty = format!(
                "[{}..{}] + [{}..{}]",
                br[0],
                br[0] + br[1],
                br[2],
                br[2] + br[3]
            );
            rows.push(("ByteRange".into(), pretty));
            rows.push((
                "Signed bytes".into(),
                format!("{} bytes", format_thousands((br[1] + br[3]) as u64)),
            ));
        }
    }
    if report.contents_size > 0 {
        rows.push(("CMS blob".into(), format!("{} bytes", report.contents_size)));
    }

    for (k, v) in rows {
        card.append(&kv_row(&k, &v, false));
    }

    card.upcast()
}

fn integrity_card(report: &SignatureReport) -> gtk::Widget {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 6);
    card.add_css_class("card");
    card.append(&section_title("Integrity — SHA-256 of signed bytes"));
    card.append(&check_outcome_widget(&report.integrity));
    card.upcast()
}

fn signature_card_check(report: &SignatureReport) -> gtk::Widget {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 6);
    card.add_css_class("card");
    card.append(&section_title("Cryptographic signature"));
    card.append(&check_outcome_widget(&report.signature));
    card.upcast()
}

fn certificate_card(cert: &CertificateSummary) -> gtk::Widget {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 6);
    card.add_css_class("card");
    card.append(&section_title("Signer certificate"));

    if !cert.present {
        card.append(&inline_banner(
            &format!("✗  {}", cert.validity_note),
            "warn",
        ));
        return card.upcast();
    }

    card.append(&kv_row("Subject", &cert.subject, false));
    card.append(&kv_row("Issuer", &cert.issuer, false));
    card.append(&kv_row("Serial", &cert.serial, true));
    card.append(&kv_row("Not before", &cert.not_before, false));
    card.append(&kv_row("Not after", &cert.not_after, false));
    card.append(&kv_row("Public key", &cert.public_key_algo, false));
    card.append(&kv_row("Signature", &cert.signature_algo, false));
    card.append(&kv_row(
        "DER size",
        &format!("{} bytes", cert.der_length),
        false,
    ));

    // Validity banner
    if cert.validity_note.starts_with("expired") {
        card.append(&inline_banner(
            &format!("⚠  Certificate EXPIRED — {}", cert.validity_note),
            "warn",
        ));
    } else if cert.validity_note == "currently valid" {
        card.append(&inline_banner("✓  Certificate is currently valid", "ok"));
    } else {
        card.append(&inline_banner(
            &format!("⚠  Certificate {}", cert.validity_note),
            "warn",
        ));
    }

    if let Some(note) = &cert.signing_time_note {
        card.append(&inline_banner(&format!("⚠  {note}"), "warn"));
    }

    card.upcast()
}

fn chain_card(chain: &ChainSummary) -> gtk::Widget {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 6);
    card.add_css_class("card");
    card.append(&section_title("Certificate chain"));

    if chain.links.is_empty() {
        card.append(&inline_banner("No chain information available", "warn"));
        return card.upcast();
    }

    // Collect every error we print for individual links, so the summary
    // line doesn't duplicate one of them.
    let mut shown_errors: Vec<String> = Vec::new();

    for (i, link) in chain.links.iter().enumerate() {
        let role = if link.self_signed { "ROOT" } else { "cert" };
        let origin = if link.from_trust_store {
            "trust store"
        } else {
            "PDF"
        };
        let badge = if link.verified { "✓" } else { "⚠" };
        let header = format!("{badge}  [{i}] {role}  (from {origin})");

        let header_label = gtk::Label::builder()
            .label(header)
            .halign(gtk::Align::Start)
            .xalign(0.0)
            .build();
        header_label.add_css_class("kv-key");
        card.append(&header_label);

        card.append(&kv_row("Subject", &link.subject, false));
        if !link.self_signed {
            card.append(&kv_row("Issuer", &link.issuer, false));
        }
        if let Some(err) = &link.error {
            card.append(&inline_banner(&format!("⚠  {err}"), "warn"));
            shown_errors.push(err.clone());
        }
    }

    // Summary line — only if it adds new information beyond the link errors.
    if chain.reached_trusted_root {
        card.append(&inline_banner("✓  Chain reaches a trusted root", "ok"));
    } else if !shown_errors.iter().any(|e| e == &chain.note) {
        card.append(&inline_banner(&format!("⚠  {}", chain.note), "warn"));
    }

    card.upcast()
}

fn signature_card(report: &SignatureReport) -> gtk::Widget {
    let card = gtk::Box::new(gtk::Orientation::Vertical, 12);
    card.add_css_class("card");
    card.set_margin_bottom(12);

    card.append(&section_title(&format!(
        "Signature — {}",
        report.field_name
    )));

    card.append(&claims_card(report));
    card.append(&integrity_card(report));
    card.append(&signature_card_check(report));
    card.append(&certificate_card(&report.certificate));
    card.append(&chain_card(&report.chain));

    card.upcast()
}

// -----------------------------------------------------------------------------
// Verdict + results
// -----------------------------------------------------------------------------

fn verdict_banner(verdict: &VerificationResult) -> gtk::Widget {
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

fn build_results_view(assessment: &Assessment) -> gtk::Widget {
    let column = gtk::Box::new(gtk::Orientation::Vertical, 12);

    column.append(&verdict_banner(&assessment.verdict));

    for report in &assessment.signatures {
        column.append(&signature_card(report));
    }

    // Wrap in a scrolled window.
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .hexpand(true)
        .build();

    let padded = gtk::Box::new(gtk::Orientation::Vertical, 0);
    padded.set_margin_top(24);
    padded.set_margin_bottom(24);
    padded.set_margin_start(24);
    padded.set_margin_end(24);
    padded.append(&column);
    scrolled.set_child(Some(&padded));

    scrolled.upcast()
}

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

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

fn main() -> adw::glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("io.github.arnab-atra.Certilens")
        .build();

    app.connect_activate(|app| {
        load_css();

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("CertiLens")
            .default_width(1100)
            .default_height(700)
            .build();

        let toolbar_view = adw::ToolbarView::new();

        let header = adw::HeaderBar::new();
        toolbar_view.add_top_bar(&header);

        let content_area = adw::Bin::new();
        let welcome = build_welcome_widget();
        content_area.set_child(Some(&welcome));
        toolbar_view.set_content(Some(&content_area));

        let content_area_for_click = content_area.clone();
        let window_for_dialog = window.clone();

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
                                Ok(assessment) => {
                                    let verdict = &assessment.verdict;
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

                                    let widget = build_results_view(&assessment);
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
                        }
                    }
                    Err(err) => {
                        println!("Cancelled: {err}");
                    }
                },
            );
        });
        header.pack_start(&open_button);

        window.set_content(Some(&toolbar_view));
        window.present();
    });

    app.run()
}
