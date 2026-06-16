#!/usr/bin/env python3
"""Generate the RansomDuck desktop app icon."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

SIZE = 1024
SCALE = 4
CANVAS = SIZE * SCALE
CENTER = SIZE // 2


def sc(value: float) -> int:
    return round(value * SCALE)


def box(values: tuple[float, float, float, float]) -> list[int]:
    return [sc(value) for value in values]


def pts(values: list[tuple[float, float]]) -> list[tuple[int, int]]:
    return [(sc(x), sc(y)) for x, y in values]


def draw_layer() -> Image.Image:
    return Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))


def composite(base: Image.Image, layer: Image.Image) -> None:
    base.alpha_composite(layer)


def draw_background(img: Image.Image) -> None:
    shadow = draw_layer()
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.ellipse(box((98, 112, 926, 940)), fill=(1, 13, 35, 120))
    shadow = shadow.filter(ImageFilter.GaussianBlur(sc(28)))
    composite(img, shadow)

    bg = draw_layer()
    bg_draw = ImageDraw.Draw(bg)
    for i in range(455, 0, -1):
        t = i / 455
        r = round(19 + 26 * t)
        g = round(72 + 112 * t)
        b = round(132 + 87 * t)
        bg_draw.ellipse(
            box((CENTER - i, CENTER - i, CENTER + i, CENTER + i)),
            fill=(r, g, b, 255),
        )
    bg_draw.ellipse(box((86, 82, 938, 934)), outline=(123, 211, 255, 170), width=sc(18))
    bg_draw.ellipse(box((134, 128, 890, 884)), outline=(255, 255, 255, 34), width=sc(8))
    composite(img, bg)


def draw_shield(img: Image.Image) -> None:
    shield_shadow = draw_layer()
    shield_shadow_draw = ImageDraw.Draw(shield_shadow)
    shield = pts(
        [
            (512, 164),
            (774, 248),
            (742, 618),
            (512, 828),
            (282, 618),
            (250, 248),
        ]
    )
    shield_shadow_draw.polygon(shield, fill=(0, 12, 32, 88))
    shield_shadow = shield_shadow.filter(ImageFilter.GaussianBlur(sc(18)))
    composite(img, shield_shadow)

    layer = draw_layer()
    draw = ImageDraw.Draw(layer)
    draw.polygon(shield, fill=(13, 44, 82, 230))
    draw.line(shield + [shield[0]], fill=(111, 207, 255, 190), width=sc(14), joint="curve")
    draw.line(
        pts([(318, 280), (512, 218), (706, 280)]),
        fill=(255, 255, 255, 46),
        width=sc(10),
        joint="curve",
    )
    composite(img, layer)


def draw_duck(img: Image.Image) -> None:
    # A single dark outline keeps the mascot readable in tiny tray sizes.
    outline = (71, 46, 20, 255)
    body = (255, 207, 56, 255)
    body_dark = (235, 160, 37, 255)
    body_light = (255, 235, 119, 255)
    beak = (255, 126, 31, 255)
    beak_dark = (205, 79, 19, 255)

    shadow = draw_layer()
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.ellipse(box((286, 685, 752, 814)), fill=(0, 13, 31, 105))
    shadow = shadow.filter(ImageFilter.GaussianBlur(sc(20)))
    composite(img, shadow)

    layer = draw_layer()
    draw = ImageDraw.Draw(layer)

    # Tail feathers.
    tail = pts([(296, 522), (178, 444), (230, 584)])
    tail_inner = pts([(292, 536), (213, 485), (246, 574)])
    draw.polygon(tail, fill=outline)
    draw.polygon(tail_inner, fill=body)

    # Body.
    draw.ellipse(box((252, 412, 728, 760)), fill=outline)
    draw.ellipse(box((278, 436, 704, 728)), fill=body)
    draw.ellipse(box((328, 482, 644, 688)), fill=(255, 219, 76, 255))

    # Neck bridge makes the head/body silhouette less like two separate blobs.
    draw.rounded_rectangle(box((500, 328, 638, 554)), radius=sc(72), fill=outline)
    draw.rounded_rectangle(box((520, 348, 618, 548)), radius=sc(58), fill=body)

    # Wing and feather cuts.
    draw.ellipse(box((318, 498, 558, 658)), fill=body_dark)
    draw.arc(box((344, 514, 526, 666)), 16, 168, fill=(180, 103, 23, 150), width=sc(11))
    draw.arc(box((386, 514, 572, 664)), 22, 166, fill=(180, 103, 23, 112), width=sc(8))
    draw.ellipse(box((376, 460, 478, 540)), fill=(255, 226, 103, 185))

    # Head.
    draw.ellipse(box((430, 220, 704, 494)), fill=outline)
    draw.ellipse(box((452, 240, 682, 472)), fill=body)
    draw.ellipse(box((492, 266, 608, 360)), fill=body_light)

    # Beak with a subtle lower lip.
    upper_beak = pts([(666, 324), (844, 366), (666, 414)])
    lower_beak = pts([(662, 394), (810, 434), (658, 458)])
    draw.polygon(upper_beak, fill=outline)
    draw.polygon(lower_beak, fill=outline)
    draw.polygon(pts([(676, 338), (806, 368), (676, 400)]), fill=beak)
    draw.polygon(pts([(674, 404), (774, 430), (672, 444)]), fill=beak_dark)
    draw.line(pts([(684, 402), (778, 422)]), fill=(96, 43, 20, 160), width=sc(6))

    # Eye and brow.
    draw.ellipse(box((572, 300, 636, 364)), fill=(255, 255, 246, 255))
    draw.ellipse(box((592, 314, 628, 350)), fill=(14, 22, 34, 255))
    draw.ellipse(box((602, 320, 612, 330)), fill=(255, 255, 255, 230))
    draw.arc(box((548, 272, 636, 326)), 196, 338, fill=(78, 50, 20, 230), width=sc(10))

    # Small highlight that gives the icon depth without looking glossy.
    draw.arc(box((362, 462, 648, 706)), 204, 315, fill=(255, 244, 166, 150), width=sc(14))

    composite(img, layer)


def main() -> None:
    img = draw_layer()
    draw_background(img)
    draw_shield(img)
    draw_duck(img)

    img = img.resize((SIZE, SIZE), Image.Resampling.LANCZOS)
    output_dir = Path(__file__).parent

    png_sizes = {
        "32x32.png": 32,
        "64x64.png": 64,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon.png": 1024,
        "Square30x30Logo.png": 30,
        "Square44x44Logo.png": 44,
        "Square71x71Logo.png": 71,
        "Square89x89Logo.png": 89,
        "Square107x107Logo.png": 107,
        "Square142x142Logo.png": 142,
        "Square150x150Logo.png": 150,
        "Square284x284Logo.png": 284,
        "Square310x310Logo.png": 310,
        "StoreLogo.png": 50,
    }
    for filename, size in png_sizes.items():
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(output_dir / filename)
        print(f"Generated {filename}")

    img.save(
        output_dir / "icon.ico",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("Generated icon.ico")

    img.save(
        output_dir / "icon.icns",
        sizes=[(16, 16), (32, 32), (64, 64), (128, 128), (256, 256), (512, 512), (1024, 1024)],
    )
    print("Generated icon.icns")


if __name__ == "__main__":
    main()
