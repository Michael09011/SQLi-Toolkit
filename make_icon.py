from PIL import Image, ImageDraw, ImageFont

size = 256
bg = (13, 17, 23, 255)
accent = (0, 255, 136, 255)
text = "SQLi"

img = Image.new("RGBA", (size, size), bg)
d = ImageDraw.Draw(img)

# Draw rounded square border
border = 18
radius = 34
for offset in range(border):
    d.rounded_rectangle(
        [offset, offset, size - offset - 1, size - offset - 1],
        radius=radius, outline=(20, 220, 140, 255)
    )

# Draw lightning bolt
bolt = [
    (size * 0.42, size * 0.18),
    (size * 0.35, size * 0.55),
    (size * 0.52, size * 0.55),
    (size * 0.42, size * 0.82),
    (size * 0.72, size * 0.38),
    (size * 0.53, size * 0.38),
]
d.polygon(bolt, fill=accent)

txt = "SQLi"
try:
    font = ImageFont.truetype("arial.ttf", 56)
except Exception:
    font = ImageFont.load_default()

try:
    bbox = d.textbbox((0, 0), txt, font=font)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
except AttributeError:
    w, h = font.getsize(txt)
d.text(
    ((size - w) / 2, size - h - 20),
    txt,
    font=font,
    fill=(255, 255, 255, 255),
)

# Create a smaller secondary badge
badge_size = 96
badge = Image.new("RGBA", (badge_size, badge_size), (0, 0, 0, 0))
d2 = ImageDraw.Draw(badge)
d2.ellipse([0, 0, badge_size - 1, badge_size - 1], fill=(36, 49, 64, 255), outline=accent)
d2.text((12, 24), "Tk", font=font if font.size <= 56 else font, fill=accent)

img.paste(badge, (size - badge_size - 20, size - badge_size - 20), badge)

img.save("icon.ico", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
