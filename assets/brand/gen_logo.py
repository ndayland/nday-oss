#!/usr/bin/env python3
"""Generate the nday brand SVGs. Run: python3 assets/brand/gen_logo.py

Letterforms are drawn by hand on a 600-unit monospace cell (x-height 550,
ascender 730, descender -200, y axis pointing up), so the output has no font
dependency.
"""
import shutil
import subprocess
from pathlib import Path

OUT = Path(__file__).parent

BG = "#0D1117"
FG = "#E6EDF3"
GREEN = "#7EE787"
INK = "#1F2328"
GREEN_ON_LIGHT = "#1A7F37"
RED = "#F85149"

CELL = 600
XH = 550
ASC = 730
DESC = -200
INK_L, INK_R = 65, 535  # visible ink extent inside a cell
CURSOR_W = 340  # narrower than a letter so it reads as a cursor, not a square


def stroke(d, s):
    return f'<path d="{d}" fill="none" stroke="currentColor" stroke-width="{s}"/>'


def poly(points):
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    return f'<polygon points="{pts}" fill="currentColor"/>'


def bowl(top, s):
    """Closed bowl between the two stems, from baseline up to `top`."""
    h = s / 2
    t, b = top - h, h
    m = (t + b) / 2
    k = (t - b) * 0.285
    return stroke(
        f"M480,{m} C480,{m + k} 410,{t} 300,{t} C190,{t} 120,{m + k} 120,{m} "
        f"C120,{m - k} 190,{b} 300,{b} C410,{b} 480,{m - k} 480,{m} Z",
        s,
    )


def glyph(ch, s):
    h = s / 2
    if ch == "n":
        t = XH - h
        return stroke(f"M120,0 V{XH}", s) + stroke(
            f"M120,350 C120,440 190,{t} 300,{t} C420,{t} 480,430 480,320 V0", s
        )
    if ch == "d":
        return bowl(XH, s) + stroke(f"M480,0 V{ASC}", s)
    if ch == "a":
        return bowl(XH, s) + stroke(f"M480,0 V{XH}", s)
    if ch == "y":
        # Two diagonals cut horizontally at x-height, the join and the tail.
        w = s * 1.058 / 2  # half of the horizontal width of a slanted stem
        left = [(120 - w, XH), (120 + w, XH), (300 + w, 30), (300 - w, 30)]
        right = [(480 - w, XH), (480 + w, XH), (220 + w, DESC), (220 - w, DESC)]
        return poly(left) + poly(right)
    if ch == "0":
        return bowl(ASC, s) + stroke("M205,215 L395,515", s * 0.8)
    if ch == "-":
        return stroke("M130,290 H470", s * 0.8)
    if ch == "+":
        return stroke("M130,290 H470", s * 0.8) + stroke("M300,120 V460", s * 0.8)
    if ch == " ":
        return ""
    raise ValueError(ch)


def text(s_chars, s):
    return "".join(
        f'<g transform="translate({i * CELL},0)">{glyph(c, s)}</g>'
        for i, c in enumerate(s_chars)
    )


def cursor(cell_index, bottom, top):
    x = cell_index * CELL + INK_L
    return f'<rect x="{x}" y="{bottom}" width="{CURSOR_W}" height="{top - bottom}" fill="{GREEN}"/>'


def svg(w, h, body, bg=BG):
    rect = f'<rect width="{w}" height="{h}" fill="{bg}"/>' if bg else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}">{rect}{body}</svg>\n'
    )


def placed(inner, x, baseline, scale, color=FG):
    """Place y-up glyph units so that unit (0,0) lands on (x, baseline)."""
    return (
        f'<g transform="translate({x:.2f},{baseline:.2f}) scale({scale},-{scale})" '
        f'color="{color}">{inner}</g>'
    )


def icon(size, pad, s, bg=BG):
    """Square `n` + cursor mark; `pad` is the margin left and right of the ink."""
    ink_w = CELL + CURSOR_W
    scale = (size - 2 * pad) / ink_w
    x = pad - INK_L * scale
    baseline = (size + XH * scale) / 2
    return svg(size, size, placed(text("n", s) + cursor(1, 0, XH), x, baseline, scale), bg)


def wordmark(cursor_bottom, cursor_top, s=110, bg=BG):
    pad = 160
    ink_w = 4 * CELL + CURSOR_W
    w = ink_w + 2 * pad
    h = ASC - DESC + 2 * pad
    body = placed(
        text("nday", s) + cursor(4, cursor_bottom, cursor_top), pad - INK_L, pad + ASC, 1
    )
    return svg(w, h, body, bg)


def og_diff():
    w, h = 1200, 630
    scale = 0.19
    row_h = 200
    top = (h - 2 * row_h) / 2
    x = (w - (6 * CELL - 2 * INK_L) * scale) / 2 - INK_L * scale
    rows = [("- 0day", RED, top), ("+ nday", GREEN, top + row_h)]
    body = ""
    for chars, color, y in rows:
        body += f'<rect x="0" y="{y}" width="{w}" height="{row_h}" fill="{color}" fill-opacity="0.13"/>'
        baseline = y + (row_h + (ASC + DESC) * scale) / 2
        body += placed(text(chars, 110), x, baseline, scale, color)
    return svg(w, h, body)


# Lifecycle stage colours, as in internal/webui/static/app.css
# (--dis --pat --ana --poc --itw --kev).
STAGES = ["#9FB0C3", "#5EB1FF", "#B79CFF", "#F5B83D", "#FF8A4C", "#FF5C6C"]


def x_banner():
    """X profile header, 1500x500: the diff rows plus a six-slot lifecycle bar.

    The 0day row has six hollow slots (nothing known yet), the nday row has
    them filled in the stage colours. The block sits right of centre because
    the avatar covers the lower-left corner of the header.
    """
    w, h = 1500, 500
    scale = 0.115
    row_h = 130
    top = (h - 2 * row_h) / 2
    sq, gap = 44, 16
    text_w = (6 * CELL - 2 * INK_L) * scale
    x0 = 440
    bar_x = x0 + text_w + 120
    rows = [("- 0day", RED, top, False), ("+ nday", GREEN, top + row_h, True)]
    body = ""
    for chars, color, y, known in rows:
        body += f'<rect x="0" y="{y}" width="{w}" height="{row_h}" fill="{color}" fill-opacity="0.13"/>'
        baseline = y + (row_h + (ASC + DESC) * scale) / 2
        body += placed(text(chars, 110), x0 - INK_L * scale, baseline, scale, color)
        sy = y + (row_h - sq) / 2
        for i, stage in enumerate(STAGES):
            sx = bar_x + i * (sq + gap)
            if known:
                body += f'<rect x="{sx:.1f}" y="{sy}" width="{sq}" height="{sq}" fill="{stage}"/>'
            else:
                body += (
                    f'<rect x="{sx + 2:.1f}" y="{sy + 2}" width="{sq - 4}" height="{sq - 4}" '
                    f'fill="none" stroke="{color}" stroke-opacity="0.55" stroke-width="4"/>'
                )
    return svg(w, h, body)


FILES = {
    "x-banner.svg": x_banner(),
    "icon.svg": icon(1024, 190, 110),
    "icon-transparent.svg": icon(1024, 190, 110, bg=None),
    "favicon.svg": icon(64, 7, 140),
    # Social avatar (X crops it to a circle and shows it at 40-48px): the mark
    # is larger and a little heavier than icon.svg, and its corners stay 18%
    # of the radius inside the circle.
    "avatar.svg": icon(1024, 150, 120),
    "wordmark.svg": wordmark(0, XH),
    "wordmark-transparent.svg": wordmark(0, XH, bg=None),
    # Dark ink for light pages (the README on GitHub's light theme).
    "wordmark-on-light.svg": wordmark(0, XH, bg=None).replace(FG, INK).replace(GREEN, GREEN_ON_LIGHT),
    "og-diff.svg": og_diff(),
}

# Copies embedded in the site binary. Share cards must be PNG (no platform
# renders an SVG og:image); the conversion uses macOS `sips`.
STATIC = OUT.parent.parent / "internal" / "webui" / "static"

if __name__ == "__main__":
    for name, content in FILES.items():
        (OUT / name).write_text(content)
        print("wrote", name)
    (STATIC / "favicon.svg").write_text(FILES["favicon.svg"])
    print("wrote", STATIC / "favicon.svg")
    if shutil.which("sips"):
        subprocess.run(
            ["sips", "-s", "format", "png", str(OUT / "og-diff.svg"), "--out", str(STATIC / "og.png")],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print("wrote", STATIC / "og.png")
        subprocess.run(
            ["sips", "-s", "format", "png", str(OUT / "avatar.svg"), "--out", str(OUT / "avatar.png")],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print("wrote", OUT / "avatar.png")
        subprocess.run(
            ["sips", "-s", "format", "png", str(OUT / "x-banner.svg"), "--out", str(OUT / "x-banner.png")],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        print("wrote", OUT / "x-banner.png")
    else:
        print("sips not found: og.png and avatar.png not regenerated")
