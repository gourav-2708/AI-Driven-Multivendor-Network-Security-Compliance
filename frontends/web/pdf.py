# -*- coding: utf-8 -*-
"""
A small PDF writer with no dependencies, enough for the dashboard's reports:
A4 pages, Helvetica in regular and bold, wrapped text, filled rectangles,
lines and polylines. Coordinates are in points from the top-left corner of
the page, y growing downwards, which is how the report code thinks.
"""

PAGE_W, PAGE_H = 595.28, 841.89          # A4 in points

# Helvetica advance widths (1/1000 em) for the printable ASCII range 32..126.
_WIDTHS = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]
_BOLD_FACTOR = 1.07                       # Helvetica-Bold runs a little wider


def _clean(text):
    """Text as Latin-1, with anything else replaced, since the base fonts stop there."""
    table = {0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"', 0x2013: "-", 0x2014: "-",
             0x2026: "...", 0x2022: "*", 0x00A0: " "}
    return str(text).translate(table).encode("latin-1", "replace").decode("latin-1")


def text_width(text, size, bold=False):
    total = 0
    for ch in _clean(text):
        code = ord(ch)
        total += _WIDTHS[code - 32] if 32 <= code <= 126 else 556
    return total * size / 1000 * (_BOLD_FACTOR if bold else 1)


def wrap(text, size, max_width, bold=False):
    """Split text into lines no wider than `max_width` points."""
    lines = []
    for paragraph in _clean(text).split("\n"):
        line = ""
        for word in paragraph.split():
            while text_width(word, size, bold) > max_width and len(word) > 1:
                # A single word wider than the column: cut it.
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > max_width:
                    cut -= 1
                if line:
                    lines.append(line)
                    line = ""
                lines.append(word[:cut])
                word = word[cut:]
            candidate = f"{line} {word}".strip()
            if text_width(candidate, size, bold) <= max_width:
                line = candidate
            else:
                lines.append(line)
                line = word
        lines.append(line)
    return lines


def _escape(text):
    return _clean(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Document:
    """Collects pages of drawing operators and serialises them as a PDF."""

    def __init__(self, title="", author="net-audit"):
        self.title, self.author = title, author
        self._pages = []
        self._ops = None
        self.add_page()

    # -- pages -------------------------------------------------------------
    def add_page(self):
        self._ops = []
        self._pages.append(self._ops)

    @property
    def page_count(self):
        return len(self._pages)

    # -- drawing -------------------------------------------------------------
    @staticmethod
    def _rgb(color):
        return "%.3f %.3f %.3f" % tuple(c / 255 for c in color)

    def text(self, x, y, text, size=10, bold=False, color=(20, 20, 20), align="left"):
        """Draw one line of text with its baseline at y."""
        if align != "left":
            w = text_width(text, size, bold)
            x -= w if align == "right" else w / 2
        self._ops.append("BT /%s %.2f Tf %s rg %.2f %.2f Td (%s) Tj ET" % (
            "F2" if bold else "F1", size, self._rgb(color), x, PAGE_H - y, _escape(text)))

    def paragraph(self, x, y, text, size=10, width=400, leading=None, bold=False,
                  color=(20, 20, 20)):
        """Draw wrapped text starting at baseline y; returns the y after the last line."""
        leading = leading or size * 1.4
        for line in wrap(text, size, width, bold):
            self.text(x, y, line, size, bold, color)
            y += leading
        return y

    def rect(self, x, y, w, h, fill=None, stroke=None, line_width=0.75):
        op = []
        if fill:
            op.append(self._rgb(fill) + " rg")
        if stroke:
            op.append(self._rgb(stroke) + " RG %.2f w" % line_width)
        op.append("%.2f %.2f %.2f %.2f re" % (x, PAGE_H - y - h, w, h))
        op.append("B" if fill and stroke else ("f" if fill else "S"))
        self._ops.append(" ".join(op))

    def line(self, x1, y1, x2, y2, color=(200, 200, 200), width=0.75):
        self._ops.append("%s RG %.2f w %.2f %.2f m %.2f %.2f l S" % (
            self._rgb(color), width, x1, PAGE_H - y1, x2, PAGE_H - y2))

    def polyline(self, points, color=(250, 88, 45), width=1.5):
        if len(points) < 2:
            return
        parts = ["%s RG %.2f w 1 j 1 J" % (self._rgb(color), width)]
        for i, (x, y) in enumerate(points):
            parts.append("%.2f %.2f %s" % (x, PAGE_H - y, "m" if i == 0 else "l"))
        parts.append("S")
        self._ops.append(" ".join(parts))

    # -- output --------------------------------------------------------------
    def render(self):
        objects = []                              # object bodies, numbered from 1

        def add(body):
            objects.append(body)
            return len(objects)

        font1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        font2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        pages_id = len(objects) + 1 + 2 * len(self._pages)      # allocated after the pages
        kids = []
        for ops in self._pages:
            stream = "\n".join(ops).encode("latin-1", "replace")
            content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
            page = add(("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Contents %d 0 R "
                        "/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> >>"
                        % (pages_id, PAGE_W, PAGE_H, content, font1, font2)).encode("ascii"))
            kids.append("%d 0 R" % page)
        assert add(("<< /Type /Pages /Kids [%s] /Count %d >>"
                    % (" ".join(kids), len(kids))).encode("ascii")) == pages_id
        catalog = add(("<< /Type /Catalog /Pages %d 0 R >>" % pages_id).encode("ascii"))
        info = add(("<< /Title (%s) /Author (%s) /Producer (net-audit) >>"
                    % (_escape(self.title), _escape(self.author))).encode("latin-1", "replace"))

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n" % (len(objects) + 1)
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += (b"trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objects) + 1, catalog, info, xref))
        return bytes(out)
