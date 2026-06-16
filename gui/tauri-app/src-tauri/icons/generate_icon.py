#!/usr/bin/env python3
"""Generate a simple duck icon for RansomDuck."""

from PIL import Image, ImageDraw

SIZE = 1024
CENTER = SIZE // 2

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Background circle: gradient-ish blue.
bg_color = (42, 112, 208, 255)  # friendly blue
shadow_color = (30, 80, 150, 180)

# Outer soft shadow.
shadow_margin = 40
draw.ellipse(
    [shadow_margin, shadow_margin, SIZE - shadow_margin, SIZE - shadow_margin],
    fill=shadow_color,
)

# Main blue circle.
margin = 60
draw.ellipse([margin, margin, SIZE - margin, SIZE - margin], fill=bg_color)

# Duck body (yellow ellipse).
body_color = (255, 204, 51, 255)
body_box = [CENTER - 180, CENTER - 40, CENTER + 200, CENTER + 260]
draw.ellipse(body_box, fill=body_color)

# Duck head (yellow circle).
head_color = body_color
head_radius = 150
head_box = [
    CENTER + 20 - head_radius,
    CENTER - 220 - head_radius,
    CENTER + 20 + head_radius,
    CENTER - 220 + head_radius,
]
draw.ellipse(head_box, fill=head_color)

# Beak (orange triangle).
beak_color = (255, 140, 40, 255)
beak_points = [
    (CENTER + 130, CENTER - 230),
    (CENTER + 280, CENTER - 210),
    (CENTER + 130, CENTER - 180),
]
draw.polygon(beak_points, fill=beak_color)

# Eye (white + black pupil).
eye_white_radius = 28
eye_x = CENTER + 50
eye_y = CENTER - 240
draw.ellipse(
    [eye_x - eye_white_radius, eye_y - eye_white_radius,
     eye_x + eye_white_radius, eye_y + eye_white_radius],
    fill=(255, 255, 255, 255),
)
pupil_radius = 12
draw.ellipse(
    [eye_x - pupil_radius + 4, eye_y - pupil_radius,
     eye_x + pupil_radius + 4, eye_y + pupil_radius],
    fill=(30, 30, 30, 255),
)

# Wing (slightly darker yellow ellipse).
wing_color = (235, 180, 40, 255)
wing_box = [CENTER - 140, CENTER + 20, CENTER + 80, CENTER + 160]
draw.ellipse(wing_box, fill=wing_color)

# Highlight on head.
highlight_color = (255, 230, 150, 120)
highlight_box = [
    CENTER - 60,
    CENTER - 300,
    CENTER + 20,
    CENTER - 220,
]
draw.ellipse(highlight_box, fill=highlight_color)

img.save("icon.png")
print("Generated icon.png")
