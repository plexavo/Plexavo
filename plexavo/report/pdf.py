"""report/pdf.py — Converts the same report_data structure generator.py
uses for HTML into a PDF, via fpdf2's native drawing API rather than
fpdf2's HTML-rendering mode.

Why native drawing instead of feeding report.html through fpdf2's
write_html(): fpdf2's HTML support is a limited subset of real CSS, not
a browser engine — fighting it to approximate report.html's actual
layout would cost more effort than it saves. Building the PDF's own
layout directly, from the same underlying data, gives full control and
avoids rendering-fidelity surprises.

WeasyPrint was NOT used here despite being the blueprint's first choice
— confirmed via current documentation that it requires manually
installing GTK/Pango/Cairo native libraries and configuring Windows
PATH entries, a well-documented, still-current source of multi-hour
installation failures on Windows specifically (the target platform
here). fpdf2 is pure Python with zero native dependencies, exactly the
blueprint's own named fallback for this situation.

A bundled DejaVu Sans TTF (report/fonts/) is used instead of fpdf2's
built-in core fonts — confirmed by direct test that the core fonts
(Latin-1 only) crash outright on em-dashes, which this project's
finding text uses constantly.

Markdown handling: Claude's output uses **bold** and `inline code`
throughout, both of which were showing up as literal asterisks/backticks
in early real reports — confirmed by reading an actual generated PDF,
not caught by any offline test. fpdf2 has native markdown support via
multi_cell(markdown=True), which handles **bold** correctly, but its
underline marker is literally "--" — which would have silently deleted
the "--" from every CLI flag in every fix command (confirmed by direct
test: "--user-name" became "user-name"). Since nothing in this project
ever intends underline formatting, that marker is disabled entirely.
fpdf2 has no native backtick/inline-code support at all, so backticks
are converted to italics (not bold — asterisks inside real IAM
wildcards like `*:*` collide with a bold marker; underscores don't),
the closest visual approximation available without hand-writing
per-character font switching.
"""

import os
import re

from fpdf import FPDF

_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")

SEVERITY_COLORS = {
    "Critical": (239, 68, 68),
    "High": (249, 115, 22),
    "Medium": (234, 179, 8),
    "Low": (107, 114, 128),
}
RATING_COLORS = {
    "Excellent": (34, 197, 94),
    "Good": (34, 197, 94),
    "Fair": (234, 179, 8),
    "Poor": (249, 115, 22),
    "Critical": (239, 68, 68),
}


class _ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.add_font("DejaVu", "", os.path.join(_FONT_DIR, "DejaVuSans.ttf"))
        self.add_font("DejaVu", "B", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf"))
        self.add_font("DejaVu", "I", os.path.join(_FONT_DIR, "DejaVuSans-Oblique.ttf"))
        self.add_font("DejaVu", "BI", os.path.join(_FONT_DIR, "DejaVuSans-BoldOblique.ttf"))
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)
        # Disabled — this project never intends underline formatting,
        # and fpdf2's default marker ("--") collides with every AWS CLI
        # flag (--user-name, --policy-arn, ...). Confirmed by direct
        # test that leaving this enabled silently deletes the "--" from
        # CLI commands, breaking them. Sentinel value that will never
        # occur in real text, rather than an empty string (which broke
        # fpdf2's internal parser in testing).
        self.MARKDOWN_UNDERLINE_MARKER = "\x01\x01\x01"

    def header(self):
        if self.page_no() == 1:
            return  # the hero block on page 1 already serves as the header
        self.set_font("DejaVu", "", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 8, text="AWS Security Report", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("DejaVu", "", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 10, text=f"Page {self.page_no()}", align="C")


def _prepare_markdown(text: str) -> str:
    """fpdf2 has no native inline-code support — approximate single-
    backtick inline code with italics (__), not bold (**): confirmed
    against real output that AWS/IAM content routinely contains literal
    asterisks inside inline code (e.g. an IAM wildcard like `*:*`), and
    wrapping that in ** collides with the content's own asterisks,
    producing garbled text like `***:***`. Double-underscores
    essentially never appear in AWS/CLI vocabulary, so italics doesn't
    have the same collision risk.

    Triple-backtick code fences (```bash ... ```) are stripped FIRST,
    separately — they share the backtick character with single-backtick
    inline code, and running the inline-code regex directly against
    fenced content partially matches inside the fence markers themselves
    (confirmed against real output: left stray single backticks at the
    start/end of code blocks). There's no good way to visually box off
    a whole multi-line block in fpdf2's simple markdown mode anyway, so
    the fence markers are just removed, leaving the code itself as
    clean, unformatted, copy-pasteable text.

    Also fixes a genuinely UNPAIRED ** — confirmed against real output
    that Claude's bold markdown isn't always symmetrically paired.
    Matters more here than cosmetically: fpdf2 TOGGLES bold on every **
    it encounters (confirmed from its source), so an odd total count
    leaves the toggle stuck "on" for all text after the last marker.
    Dropping exactly the last occurrence restores an even count without
    disturbing any earlier span that was already correctly paired."""
    text = re.sub(r"```[a-zA-Z]*\n?", "", text)
    text = text.replace("```", "")
    text = re.sub(r"`(.+?)`", r"__\1__", text)
    if text.count("**") % 2 != 0:
        last_idx = text.rfind("**")
        text = text[:last_idx] + text[last_idx + 2:]
    return text


def generate_pdf(report_data: dict, output_path: str) -> None:
    """Write report_data out as a PDF at output_path."""
    pdf = _ReportPDF()
    pdf.add_page()

    # --- Masthead ---
    pdf.set_font("DejaVu", "B", 18)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 10, text="AWS Security Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(110, 110, 110)
    pdf.cell(0, 6, text=f"Account {report_data['account_id']}  |  {report_data['scan_date']}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Score hero ---
    rating = report_data["rating"]
    rc = RATING_COLORS.get(rating, (100, 100, 100))
    pdf.set_font("DejaVu", "B", 36)
    pdf.set_text_color(*rc)
    pdf.cell(60, 18, text=f"{report_data['score']}/100", new_x="RIGHT", new_y="TOP")
    pdf.set_font("DejaVu", "B", 12)
    pdf.cell(0, 18, text=rating, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", "", 10)
    pdf.set_text_color(80, 80, 80)
    total = report_data["total_findings"]
    pdf.cell(0, 8, text=f"{total} finding{'s' if total != 1 else ''} identified", new_x="LMARGIN", new_y="NEXT")

    if report_data["counts_by_category"]:
        cat_line = "   ".join(f"{n} {cat}" for cat, n in sorted(report_data["counts_by_category"].items()))
        pdf.set_font("DejaVu", "", 9)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(0, 8, text=cat_line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # --- Findings, grouped by severity ---
    for sev in report_data["severity_order"]:
        items = report_data["findings_by_severity"][sev]
        if not items:
            continue
        sc = SEVERITY_COLORS[sev]

        pdf.set_font("DejaVu", "B", 12)
        pdf.set_text_color(*sc)
        pdf.cell(0, 10, text=f"{sev} — {len(items)}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(*sc)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

        for f in items:
            _write_finding_card(pdf, f, sc)

    pdf.output(output_path)


def _write_finding_card(pdf: FPDF, f: dict, sev_color: tuple) -> None:
    """One finding, as a left-bordered block. Draws the colored border
    only if the card's content stayed on one page — fpdf2 can't draw
    backward onto a page it has already auto-page-broken past, so a
    card whose content is long enough to span two pages skips the
    border rather than draw a line across two unrelated coordinate
    spaces (which would land in the wrong place, not just look
    slightly off). The text content itself is unaffected either way."""
    start_y = pdf.get_y()
    start_page = pdf.page_no()
    left = pdf.l_margin
    content_x = left + 4
    content_w = pdf.w - pdf.r_margin - content_x

    pdf.set_xy(content_x, start_y)
    pdf.set_font("DejaVu", "B", 9)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 6, text=f"{f['check_id']}   {f['resource']}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(content_x)

    if f["explained"]:
        _write_labeled_block(pdf, content_x, content_w, "WHAT'S WRONG", f["whats_wrong"])
        _write_labeled_block(pdf, content_x, content_w, "WHAT AN ATTACKER DOES", f["attacker_does"])
        _write_labeled_block(pdf, content_x, content_w, "HOW TO FIX", f["how_to_fix"], mono=True)
    else:
        pdf.set_x(content_x)
        pdf.set_font("DejaVu", "", 9.5)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(content_w, 5.2, text=_prepare_markdown(f["whats_wrong"]), markdown=True, align="L", new_x="LMARGIN", new_y="NEXT")

    if pdf.page_no() == start_page:
        end_y = pdf.get_y()
        pdf.set_draw_color(*sev_color)
        pdf.set_line_width(0.8)
        pdf.line(left, start_y, left, end_y)
        pdf.set_line_width(0.2)
    pdf.ln(4)


def _write_labeled_block(pdf: FPDF, x: float, w: float, label: str, text: str, mono: bool = False) -> None:
    if not text:
        return
    pdf.set_x(x)
    pdf.set_font("DejaVu", "B", 7.5)
    pdf.set_text_color(130, 130, 130)
    pdf.cell(0, 5, text=label, new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(x)
    pdf.set_font("DejaVu", "", 9 if not mono else 8.5)
    pdf.set_text_color(40, 40, 40)
    pdf.multi_cell(w, 5.0, text=_prepare_markdown(text), markdown=True, align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1.5)
