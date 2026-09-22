"""Verification view — card-based layout for a document's evidence.

The view is strictly presentational: every value comes from Rust.
"""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

import certilens

# ---------------------------------------------------------------------------
# Widget helpers
# ---------------------------------------------------------------------------


def _card(subtle: bool = False) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    box.add_css_class("card")
    if subtle:
        box.add_css_class("subtle")
    return box


def _section_title(text: str) -> Gtk.Label:
    label = Gtk.Label(label=text)
    label.set_halign(Gtk.Align.START)
    label.set_xalign(0.0)
    label.add_css_class("section-title")
    return label


def _kv(key: str, value: str, *, mono: bool = False) -> Gtk.Box:
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)

    k = Gtk.Label(label=key)
    k.set_halign(Gtk.Align.START)
    k.set_xalign(0.0)
    k.set_size_request(160, -1)
    k.add_css_class("kv-key")

    v = Gtk.Label(label=value)
    v.set_halign(Gtk.Align.START)
    v.set_xalign(0.0)
    v.set_selectable(True)
    v.set_wrap(True)
    v.add_css_class("kv-mono" if mono else "kv-value")

    row.append(k)
    row.append(v)
    return row


def _status_pill(text: str, kind: str) -> Gtk.Label:
    label = Gtk.Label(label=text)
    label.set_halign(Gtk.Align.START)
    label.set_xalign(0.0)
    label.add_css_class("status")
    label.add_css_class(kind)
    return label


def _inline(text: str, kind: str = "warn") -> Gtk.Label:
    label = Gtk.Label(label=text)
    label.set_halign(Gtk.Align.FILL)
    label.set_xalign(0.0)
    label.set_wrap(True)
    label.add_css_class("inline-ok" if kind == "ok" else "inline-warn")
    return label


def _block_hex(hex_str: str, block: int = 8) -> str:
    return " ".join(hex_str[i : i + block] for i in range(0, len(hex_str), block))


# ---------------------------------------------------------------------------
# The view
# ---------------------------------------------------------------------------


class VerificationView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)

        self._scrolled = Gtk.ScrolledWindow()
        self._scrolled.set_vexpand(True)
        self._scrolled.set_hexpand(True)
        self._scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self._inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        self._inner.set_margin_top(20)
        self._inner.set_margin_bottom(28)
        self._inner.set_margin_start(24)
        self._inner.set_margin_end(24)

        self._scrolled.set_child(self._inner)
        self.append(self._scrolled)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, path: str) -> None:
        self._clear()

        try:
            doc = certilens.open_document(path)
        except Exception as exc:
            self._inner.append(self._error_card("Could not open document", str(exc)))
            return

        # ---- Verdict banner (Phase 3) ----
        try:
            verdict = doc.verify()
            self._inner.append(self._verdict_banner(verdict))
        except Exception as exc:
            self._inner.append(self._error_card("Verdict computation failed", str(exc)))

        # ---- Document header ----
        self._inner.append(self._header(str(doc.path)))

        if doc.format != "PDF":
            self._inner.append(
                self._simple_card(
                    f"Format: {doc.format} — verification not yet implemented"
                )
            )
            return

        try:
            info = doc.pdf_info()
        except Exception as exc:
            self._inner.append(self._error_card("PDF inspection failed", str(exc)))
            return

        self._inner.append(self._file_card(info))

        if info.signature_fields:
            self._inner.append(self._sig_fields_card(info))

        for idx, sig in enumerate(info.signature_details):
            self._inner.append(self._signature_card(doc, info, sig, idx))

        if not info.signature_details:
            self._inner.append(
                self._simple_card("No digital signatures found in this PDF.")
            )

    # ------------------------------------------------------------------
    # Widget construction
    # ------------------------------------------------------------------

    def _clear(self) -> None:
        child = self._inner.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._inner.remove(child)
            child = nxt

    def _verdict_banner(self, verdict) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.add_css_class("verdict-banner")
        box.add_css_class(verdict.severity_class)

        headline = Gtk.Label(label=verdict.headline)
        headline.set_halign(Gtk.Align.START)
        headline.set_xalign(0.0)
        headline.set_wrap(True)
        headline.add_css_class("verdict-headline")
        box.append(headline)

        if verdict.subtitle:
            subtitle = Gtk.Label(label=verdict.subtitle)
            subtitle.set_halign(Gtk.Align.START)
            subtitle.set_xalign(0.0)
            subtitle.set_wrap(True)
            subtitle.add_css_class("verdict-subtitle")
            box.append(subtitle)

        if verdict.issues:
            sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
            sep.set_margin_top(8)
            sep.set_margin_bottom(4)
            box.append(sep)

            for issue in verdict.issues:
                row = Gtk.Label(label=f"•  {issue}")
                row.set_halign(Gtk.Align.START)
                row.set_xalign(0.0)
                row.set_wrap(True)
                row.add_css_class("verdict-subtitle")
                box.append(row)

        return box

    def _header(self, path: str) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title = Gtk.Label(label="Document")
        title.set_halign(Gtk.Align.START)
        title.set_xalign(0.0)
        title.add_css_class("title-1")

        p = Gtk.Label(label=path)
        p.set_halign(Gtk.Align.START)
        p.set_xalign(0.0)
        p.set_selectable(True)
        p.set_wrap(True)
        p.add_css_class("big-path")

        box.append(title)
        box.append(p)
        return box

    def _simple_card(self, text: str) -> Gtk.Widget:
        card = _card()
        label = Gtk.Label(label=text)
        label.set_halign(Gtk.Align.START)
        label.set_xalign(0.0)
        label.set_wrap(True)
        card.append(label)
        return card

    def _error_card(self, title: str, detail: str) -> Gtk.Widget:
        card = _card()
        card.append(_section_title(title))
        d = Gtk.Label(label=detail)
        d.set_halign(Gtk.Align.START)
        d.set_xalign(0.0)
        d.set_wrap(True)
        d.add_css_class("mono")
        card.append(d)
        return card

    def _file_card(self, info) -> Gtk.Widget:
        card = _card()
        card.append(_section_title("PDF structure"))

        grid = Gtk.Grid()
        grid.set_column_spacing(12)
        grid.set_row_spacing(6)

        rows = [
            ("PDF version", info.version),
            ("Pages", str(info.pages)),
            ("Encrypted", "yes" if info.encrypted else "no"),
            ("Objects", str(info.object_count)),
            ("File size", f"{info.file_size:,} bytes"),
            ("EOF markers", str(info.eof_marker_count)),
            ("Incremental updates", str(info.incremental_updates)),
        ]
        if info.startxref_offset is not None:
            rows.append(("startxref offset", f"{info.startxref_offset:,}"))

        for i, (k, v) in enumerate(rows):
            grid.attach(_kv(k, v), 0, i, 1, 1)

        card.append(grid)

        if info.incremental_updates > 0:
            card.append(
                _inline(
                    "⚠  The file has been appended to after the first "
                    "EOF — the original signature may not cover the tail."
                )
            )
        return card

    def _sig_fields_card(self, info) -> Gtk.Widget:
        card = _card()
        card.append(_section_title(f"Signature fields ({len(info.signature_fields)})"))
        for f in info.signature_fields:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            pill = _status_pill(
                "signed" if f.has_value else "empty",
                "ok" if f.has_value else "warn",
            )
            name = Gtk.Label(label=f"{f.name}   (obj {f.object_id})")
            name.set_halign(Gtk.Align.START)
            name.set_xalign(0.0)
            row.append(pill)
            row.append(name)
            card.append(row)
        return card

    def _signature_card(self, doc, info, sig, idx: int) -> Gtk.Widget:
        card = _card()
        card.append(_section_title(f"Signature #{idx} — {sig.field_name}"))

        # ---- Claims from the PDF dictionary ----
        claims = _card(subtle=True)
        claims.append(_section_title("Claims in the PDF"))
        for k, v in [
            ("Filter", sig.filter),
            ("SubFilter", sig.sub_filter),
            ("Claimed signer", sig.claimed_signer),
            ("Claimed time", sig.claimed_time),
            ("Reason", sig.reason),
            ("Location", sig.location),
        ]:
            if v:
                claims.append(_kv(k, v))

        if sig.byte_range is not None:
            br = sig.byte_range
            if len(br) == 4:
                claims.append(
                    _kv(
                        "ByteRange",
                        f"[{br[0]}..{br[0] + br[1]}] + [{br[2]}..{br[2] + br[3]}]",
                    )
                )
                claims.append(_kv("Signed bytes", f"{br[1] + br[3]:,} bytes"))
            else:
                claims.append(_kv("ByteRange", str(br)))

        if sig.contents_size:
            claims.append(_kv("CMS blob", f"{sig.contents_size:,} bytes"))
        card.append(claims)

        card.append(self._digest_section(doc, idx))
        card.append(self._signature_crypto_section(doc, idx))
        card.append(self._certificate_section(doc, idx, sig))
        card.append(self._chain_section(doc, idx))

        return card

    def _digest_section(self, doc, idx: int) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(_section_title("Integrity — SHA-256 of signed bytes"))

        try:
            check = certilens.check_signature_digest(str(doc.path), idx)
        except Exception as exc:
            box.append(_inline(f"Digest check failed: {exc}", "warn"))
            return box

        algo = check["algorithm"] or "unknown"
        computed = _block_hex(check["computed"].hex())
        claimed = _block_hex(check["claimed"].hex())

        box.append(_kv("Algorithm", algo))
        box.append(_kv("Computed", computed, mono=True))
        box.append(_kv("CMS claims", claimed, mono=True))

        if check["matches"]:
            box.append(
                _inline(
                    "✓  Digest matches — the signed bytes have not been "
                    "modified since signing.",
                    "ok",
                )
            )
        else:
            box.append(
                _inline(
                    "✗  DIGEST MISMATCH — the document was modified after signing.",
                    "warn",
                )
            )
        return box

    def _signature_crypto_section(self, doc, idx: int) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(
            _section_title("Cryptographic signature (RSA over signed attributes)")
        )

        try:
            check = certilens.verify_signature(str(doc.path), idx)
        except Exception as exc:
            box.append(_inline(f"Signature verification failed to run: {exc}"))
            return box

        algo = check["digest_algorithm"] or "unknown"
        box.append(_kv("Digest algorithm", algo))
        box.append(_kv("Signature size", f"{check['signature_length']} bytes"))

        if check["valid"]:
            box.append(
                _inline(
                    "✓  Signature verifies — the signed attributes were "
                    "produced by the private key matching the signer "
                    "certificate.",
                    "ok",
                )
            )
        else:
            detail = check.get("error") or "signature did not verify"
            box.append(_inline(f"✗  Signature INVALID — {detail}", "warn"))
        return box

    def _certificate_section(self, doc, idx: int, sig) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(_section_title("Signer certificate"))

        try:
            cert = certilens.extract_signer_certificate(str(doc.path), idx)
        except Exception as exc:
            box.append(_inline(f"Certificate extraction failed: {exc}", "warn"))
            return box

        box.append(_kv("Subject", cert["subject"]))
        box.append(_kv("Issuer", cert["issuer"]))
        box.append(_kv("Serial", cert["serial_hex"], mono=True))
        box.append(_kv("Not before", cert["not_before"]))
        box.append(_kv("Not after", cert["not_after"]))
        box.append(
            _kv(
                "Public key",
                f"{cert['public_key_algorithm']}  ({cert['public_key_oid']})",
            )
        )
        box.append(
            _kv(
                "Signature",
                f"{cert['signature_algorithm']}  ({cert['signature_oid']})",
            )
        )
        box.append(_kv("DER size", f"{cert['der_length']:,} bytes"))

        if cert.get("is_expired"):
            box.append(
                _inline(
                    "⚠  The certificate is EXPIRED — its validity window has passed.",
                )
            )
        elif cert.get("currently_valid"):
            box.append(_inline("✓  Certificate is currently valid.", "ok"))
        else:
            box.append(
                _inline(
                    "⚠  Certificate is not yet valid — its not_before is in the future."
                )
            )

        if sig.claimed_time and cert.get("not_before") and cert.get("not_after"):
            ct = sig.claimed_time
            if ct.startswith("D:") and len(ct) >= 10:
                ymd = ct[2:10]
                not_before_ymd = cert["not_before"][:10].replace("-", "")
                not_after_ymd = cert["not_after"][:10].replace("-", "")

                if ymd > not_after_ymd:
                    box.append(
                        _inline(
                            "⚠  The claimed signing time is AFTER the "
                            "certificate expiry. The signature cannot be "
                            "validly attributed to this certificate."
                        )
                    )
                elif ymd < not_before_ymd:
                    box.append(
                        _inline(
                            "⚠  The claimed signing time is BEFORE the "
                            "certificate became valid."
                        )
                    )
                else:
                    box.append(
                        _inline(
                            "✓  The claimed signing time falls within the "
                            "certificate's validity window.",
                            "ok",
                        )
                    )
        return box

    def _chain_section(self, doc, idx: int) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.append(_section_title("Certificate chain"))

        try:
            report = certilens.verify_certificate_chain(str(doc.path), idx)
        except Exception as exc:
            box.append(_inline(f"Chain verification failed: {exc}"))
            return box

        links = report["links"]
        if not links:
            box.append(_inline("No certificates found in CMS."))
            return box

        for i, link in enumerate(links):
            step = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            badge = _status_pill(
                "verified" if link["verified"] else "incomplete",
                "ok" if link["verified"] else "warn",
            )
            step.append(badge)

            text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)

            role = Gtk.Label(label=f"[{i}] {'ROOT' if link['self_signed'] else 'cert'}")
            role.set_halign(Gtk.Align.START)
            role.set_xalign(0.0)
            role.add_css_class("kv-key")
            text.append(role)

            subj = Gtk.Label(label=link["subject"])
            subj.set_halign(Gtk.Align.START)
            subj.set_xalign(0.0)
            subj.set_wrap(True)
            subj.add_css_class("kv-value")
            text.append(subj)

            if not link["self_signed"]:
                iss = Gtk.Label(label=f"issued by: {link['issuer']}")
                iss.set_halign(Gtk.Align.START)
                iss.set_xalign(0.0)
                iss.set_wrap(True)
                iss.add_css_class("kv-key")
                text.append(iss)

            step.append(text)
            box.append(step)

            if link.get("error"):
                box.append(_inline(f"⚠ {link['error']}"))

        if report["reaches_root"]:
            box.append(
                _inline(
                    "✓  Chain verifies all the way up to a self-signed "
                    "root certificate.",
                    "ok",
                )
            )
            if report["root_subject"]:
                box.append(_kv("Root", report["root_subject"]))
            box.append(
                _inline(
                    "⚠  Note: a self-signed root was reached, but its "
                    "trustworthiness has not yet been checked against a "
                    "trust store. (Phase 2d-iii)"
                )
            )
        elif report["missing_issuer"]:
            box.append(
                _inline(
                    "⚠  Chain is incomplete — the issuer certificate "
                    "is not embedded in the PDF. To fully verify, the "
                    "CA cert must be provided locally or fetched from "
                    "the issuer's AIA URL. (Phase 2d-ii/iii)"
                )
            )
        else:
            box.append(_inline("⚠  Chain could not be verified to a self-signed root."))
        return box
