import os
import math
from PIL import Image, ImageDraw, ImageFont, ImageFilter, ImageOps

W, H = 3456, 4608
poster_dir = r"c:\Users\louky\OneDrive\Pictures\Desktop\SIH\sih26106-threat-platform\POSTER"
output_path = os.path.join(poster_dir, "Final_Exhibition_Poster.png")

# Fonts
font_dir = r"C:\Windows\Fonts"
def get_font(name, size):
    path = os.path.join(font_dir, name)
    try:
        return ImageFont.truetype(path, size)
    except:
        return ImageFont.load_default()

font_title_bold = get_font("segoeuib.ttf", 82)
font_title_sub = get_font("segoeui.ttf", 44)
font_badge = get_font("segoeuib.ttf", 32)
font_card_title = get_font("segoeuib.ttf", 36)
font_card_desc = get_font("segoeui.ttf", 26)
font_metric_num = get_font("segoeuib.ttf", 64)
font_metric_label = get_font("segoeuib.ttf", 26)
font_footer = get_font("segoeui.ttf", 30)
font_footer_bold = get_font("segoeuib.ttf", 32)

print("Creating high-resolution canvas (3456 x 4608)...")
# Base Canvas with dark cyber gradient
canvas = Image.new("RGBA", (W, H), (10, 15, 26, 255))
draw = ImageDraw.Draw(canvas)

# Background subtle cyber grid & ambient glows
for y in range(0, H, 120):
    draw.line([(0, y), (W, y)], fill=(16, 24, 42, 100), width=1)
for x in range(0, W, 120):
    draw.line([(x, 0), (x, H)], fill=(16, 24, 42, 100), width=1)

# Top & Corner Ambient Glows
glow_overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
glow_draw = ImageDraw.Draw(glow_overlay)
glow_draw.ellipse([(-300, -300), (1200, 800)], fill=(99, 102, 241, 35)) # Indigo glow top-left
glow_draw.ellipse([(W - 1200, -300), (W + 300, 800)], fill=(6, 182, 212, 35)) # Cyan glow top-right
glow_draw.ellipse([(W//2 - 600, H - 900), (W//2 + 600, H + 300)], fill=(16, 185, 129, 25)) # Emerald glow bottom
glow_overlay = glow_overlay.filter(ImageFilter.GaussianBlur(120))
canvas = Image.alpha_composite(canvas, glow_overlay)
draw = ImageDraw.Draw(canvas)

# ==============================================================================
# 1. HEADER SECTION (y: 60 to 480)
# ==============================================================================
header_box = [60, 60, W - 60, 500]
draw.rounded_rectangle(header_box, radius=24, fill=(15, 23, 42, 230), outline=(51, 65, 85, 255), width=2)
# Glowing top accent line
draw.line([(80, 62), (W - 80, 62)], fill=(99, 102, 241, 255), width=4)

# College Logo (Top Left)
logo_path = os.path.join(poster_dir, "Logo.png")
if os.path.exists(logo_path):
    with Image.open(logo_path) as logo_img:
        logo_img = logo_img.convert("RGBA")
        # Target height ~180px
        l_h = 170
        l_w = int(logo_img.width * (l_h / logo_img.height))
        logo_resized = logo_img.resize((l_w, l_h), Image.Resampling.LANCZOS)
        # Background card for logo
        logo_card = [90, 85, 90 + l_w + 30, 85 + l_h + 30]
        draw.rounded_rectangle(logo_card, radius=16, fill=(255, 255, 255, 245), outline=(99, 102, 241, 180), width=2)
        canvas.paste(logo_resized, (105, 100), logo_resized)
        logo_right = 105 + l_w + 50
else:
    logo_right = 100

# Presenter Photo (Top Right)
photo_path = os.path.join(poster_dir, "Loopic.jpeg")
if os.path.exists(photo_path):
    with Image.open(photo_path) as photo_img:
        photo_img = photo_img.convert("RGBA")
        p_target_w, p_target_h = 240, 300
        # Crop to aspect ratio then resize
        cropped_photo = ImageOps.fit(photo_img, (p_target_w, p_target_h), Image.Resampling.LANCZOS)
        # Create mask with rounded corners
        mask = Image.new("L", (p_target_w, p_target_h), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.rounded_rectangle([0, 0, p_target_w, p_target_h], radius=20, fill=255)
        
        px = W - 90 - p_target_w
        py = 85
        # Frame
        draw.rounded_rectangle([px - 4, py - 4, px + p_target_w + 4, py + p_target_h + 4], radius=24, outline=(6, 182, 212, 255), width=3)
        canvas.paste(cropped_photo, (px, py), mask)
        
        # Presenter label
        draw.text((px - 320, py + 80), "RESEARCH LEAD &", font=font_badge, fill=(148, 163, 184))
        draw.text((px - 320, py + 125), "LEAD DEVELOPER", font=font_card_title, fill=(255, 255, 255))
        draw.text((px - 320, py + 180), "Cybersecurity Dept.", font=font_card_desc, fill=(6, 182, 212))

# Center Titles
title_x = logo_right + 40
draw.rounded_rectangle([title_x, 85, title_x + 650, 135], radius=25, fill=(99, 102, 241, 50), outline=(99, 102, 241, 150), width=2)
draw.text((title_x + 25, 93), "INSTITUTIONAL CYBERSECURITY & DEFENSE", font=font_badge, fill=(165, 180, 252))

draw.text((title_x, 150), "AI-POWERED EMAIL THREAT DETECTION", font=font_title_bold, fill=(255, 255, 255))
draw.text((title_x, 245), "& DIGITAL FORENSIC INTELLIGENCE PLATFORM", font=font_title_bold, fill=(99, 102, 241))
draw.text((title_x, 345), "Multi-Hop Reverse MTA Route Tracing  |  Explainable Factor Attribution  |  Zero-Trust Heuristics", font=font_title_sub, fill=(148, 163, 184))

# Live Portal Pill
pill_box = [title_x, 415, title_x + 940, 475]
draw.rounded_rectangle(pill_box, radius=30, fill=(6, 182, 212, 35), outline=(6, 182, 212, 180), width=2)
draw.text((title_x + 25, 427), "🌐 Production Deployment: https://sih26106-threat-platform.vercel.app", font=font_card_title, fill=(103, 232, 249))

# ==============================================================================
# 2. KEY METRICS RIBBON (y: 530 to 730)
# ==============================================================================
metrics = [
    ("20-STAGE", "Forensic Pipeline", "RFC 2822 MIME, SPF/DKIM, Geo, URLs, Attachments & NLP", (99, 102, 241)),
    ("0 – 100", "Attributed Threat Score", "Transparent dynamic factor points with explicit proof citations", (239, 68, 68)),
    ("100% SSRF-SAFE", "Zero-Trust Link Analysis", "In-memory lexical entropy & anchor deception (Zero outbound HTTP)", (16, 185, 129)),
    ("< 120ms", "Real-Time Latency", "Offline-first dual-engine classifier & in-memory LRU Geo cache", (245, 158, 11)),
]

card_w = (W - 120 - (len(metrics) - 1) * 30) // len(metrics)
for i, (m_val, m_title, m_desc, m_color) in enumerate(metrics):
    cx = 60 + i * (card_w + 30)
    cy = 530
    box = [cx, cy, cx + card_w, cy + 200]
    draw.rounded_rectangle(box, radius=18, fill=(15, 23, 42, 220), outline=(30, 41, 59, 255), width=2)
    # Top mini accent
    draw.rounded_rectangle([cx + 20, cy, cx + 120, cy + 4], radius=2, fill=m_color)
    draw.text((cx + 25, cy + 25), m_val, font=font_metric_num, fill=m_color)
    draw.text((cx + 25, cy + 105), m_title, font=font_card_title, fill=(255, 255, 255))
    draw.text((cx + 25, cy + 150), m_desc, font=get_font("segoeui.ttf", 22), fill=(148, 163, 184))

# ==============================================================================
# 3. SCREENSHOTS SHOWCASE (Showcasing all 5 screenshots)
# ==============================================================================
screenshots = [f for f in sorted(os.listdir(poster_dir)) if f.startswith("Screenshot") and f.endswith(".png")]
print(f"Found {len(screenshots)} screenshots to place.")

def frame_screenshot(img_path, title, subtitle, target_w, target_h):
    """Creates a macOS/Terminal styled card containing the screenshot."""
    card = Image.new("RGBA", (target_w, target_h), (15, 23, 42, 240))
    cdraw = ImageDraw.Draw(card)
    cdraw.rounded_rectangle([0, 0, target_w, target_h], radius=18, fill=(15, 23, 42, 240), outline=(51, 65, 85, 255), width=2)
    
    # Top title bar
    title_bar_h = 70
    cdraw.rounded_rectangle([0, 0, target_w, title_bar_h], radius=18, fill=(30, 41, 59, 255))
    cdraw.rectangle([0, title_bar_h - 18, target_w, title_bar_h], fill=(30, 41, 59, 255))
    
    # Window Dots
    cdraw.ellipse([25, 26, 43, 44], fill=(239, 68, 68)) # Red
    cdraw.ellipse([53, 26, 71, 44], fill=(245, 158, 11)) # Yellow
    cdraw.ellipse([81, 26, 99, 44], fill=(16, 185, 129)) # Green
    
    cdraw.text((125, 20), title, font=font_card_title, fill=(255, 255, 255))
    if subtitle:
        cdraw.text((target_w - 650, 24), subtitle, font=font_card_desc, fill=(6, 182, 212))
        
    # Resize screenshot preserving aspect ratio
    with Image.open(img_path) as ss:
        ss = ss.convert("RGBA")
        inner_w = target_w - 24
        inner_h = target_h - title_bar_h - 16
        # Fit image maintaining ratio
        fitted_ss = ImageOps.fit(ss, (inner_w, inner_h), Image.Resampling.LANCZOS)
        card.paste(fitted_ss, (12, title_bar_h + 6), fitted_ss)
        
    return card

# Top Spotlight Screenshot: Screenshot 1 (Dashboard) + Side Highlights Box
top_y = 760
top_h = 1380
hero_w = 2240

card_titles = [
    ("1. EXECUTIVE SOC COMMAND DASHBOARD", "Real-Time Telemetry & Metric Gauges"),
    ("2. FORENSIC INGESTION & DECODING GATEWAY", "MIME Extraction & Multi-Charset Decoders"),
    ("3. REVERSE CHRONOLOGICAL NETWORK HOP MAP", "Interactive Leaflet Route Traversal"),
    ("4. THREAT SCORING & FACTOR ATTRIBUTION", "Dynamic Point Attribution (0–100)"),
    ("5. COURT-ADMISSIBLE FORENSIC CASE DOSSIER", "Two-Pass PDF & Machine-Readable JSON"),
]

# Hero Screenshot 1
if len(screenshots) > 0:
    ss1_card = frame_screenshot(os.path.join(poster_dir, screenshots[0]), card_titles[0][0], card_titles[0][1], hero_w, top_h)
    canvas.paste(ss1_card, (60, top_y), ss1_card)

# Side Highlights Card next to Hero
side_x = 60 + hero_w + 30
side_w = W - side_x - 60
side_card = Image.new("RGBA", (side_w, top_h), (15, 23, 42, 240))
sdraw = ImageDraw.Draw(side_card)
sdraw.rounded_rectangle([0, 0, side_w, top_h], radius=18, fill=(15, 23, 42, 240), outline=(99, 102, 241, 150), width=2)

# Side Card Header
sdraw.rounded_rectangle([0, 0, side_w, 70], radius=18, fill=(99, 102, 241, 40))
sdraw.text((30, 20), "CORE FORENSIC INNOVATIONS", font=font_card_title, fill=(165, 180, 252))

# Bullet Points / Architectural Features
bullets = [
    ("REVERSE MTA ROUTE TRACING", "RFC 2822 Received headers are parsed chronologically in reverse order, extracting genuine IP addresses, eliminating internal private LANs, and mapping real-time geographic flight polylines."),
    ("HONEST PROVENANCE STANDARDS", "Never fabricates threat intelligence. Strictly labels feeds as Verified Live Provider, Internal Heuristics, or Lab Simulation. Unavailable APIs gracefully fallback without failure."),
    ("SSRF-SAFE URL & CRYPTO ENGINE", "Extracts hidden hyperlinks, detects anchor-text destination mismatches, high-entropy query tokens, and ransomware Bitcoin/Ethereum wallet addresses without outbound web requests."),
    ("AIR-GAPPED OFFLINE DUAL NLP", "High-accuracy intent classification combining scikit-learn TF-IDF model with deterministic heuristic rules to flag artificial urgency, executive coercion, and credential harvesting."),
    ("CHAIN-OF-CUSTODY AUDITING", "Enterprise SOC case triage workflows (New, In-Progress, Escalated, Closed), persistent analyst shift notes, and two-pass ReportLab PDF generation for compliance records.")
]

by = 100
for b_title, b_desc in bullets:
    sdraw.rounded_rectangle([25, by, side_w - 25, by + 230], radius=12, fill=(30, 41, 59, 140), outline=(51, 65, 85, 180), width=1)
    sdraw.text((45, by + 18), "▶  " + b_title, font=font_card_title, fill=(6, 182, 212))
    
    # Word wrap description
    words = b_desc.split()
    lines = []
    curr = ""
    for w in words:
        if len(curr + " " + w) > 48:
            lines.append(curr)
            curr = w
        else:
            curr = curr + " " + w if curr else w
    if curr:
        lines.append(curr)
        
    for li, line_text in enumerate(lines[:4]):
        sdraw.text((45, by + 70 + li * 36), line_text, font=font_card_desc, fill=(203, 213, 225))
    by += 250

canvas.paste(side_card, (side_x, top_y), side_card)

# ==============================================================================
# 4. LOWER 2x2 GRID (Screenshots 2, 3, 4, 5)
# ==============================================================================
grid_y1 = top_y + top_h + 35
grid_w = (W - 120 - 30) // 2 # ~1623px
grid_h = 1040

# Screenshot 2 (Bottom Left 1)
if len(screenshots) > 1:
    ss2_card = frame_screenshot(os.path.join(poster_dir, screenshots[1]), card_titles[1][0], card_titles[1][1], grid_w, grid_h)
    canvas.paste(ss2_card, (60, grid_y1), ss2_card)

# Screenshot 3 (Bottom Right 1)
if len(screenshots) > 2:
    ss3_card = frame_screenshot(os.path.join(poster_dir, screenshots[2]), card_titles[2][0], card_titles[2][1], grid_w, grid_h)
    canvas.paste(ss3_card, (60 + grid_w + 30, grid_y1), ss3_card)

grid_y2 = grid_y1 + grid_h + 30

# Screenshot 4 (Bottom Left 2)
if len(screenshots) > 3:
    ss4_card = frame_screenshot(os.path.join(poster_dir, screenshots[3]), card_titles[3][0], card_titles[3][1], grid_w, grid_h)
    canvas.paste(ss4_card, (60, grid_y2), ss4_card)

# Screenshot 5 (Bottom Right 2)
if len(screenshots) > 4:
    ss5_card = frame_screenshot(os.path.join(poster_dir, screenshots[4]), card_titles[4][0], card_titles[4][1], grid_w, grid_h)
    canvas.paste(ss5_card, (60 + grid_w + 30, grid_y2), ss5_card)

# ==============================================================================
# 5. FOOTER BANNER (y: 4320 to 4540)
# ==============================================================================
footer_y = H - 240
footer_box = [60, footer_y, W - 60, H - 60]
draw.rounded_rectangle(footer_box, radius=20, fill=(15, 23, 42, 240), outline=(51, 65, 85, 255), width=2)
draw.line([(80, footer_y + 2), (W - 80, footer_y + 2)], fill=(6, 182, 212, 255), width=3)

# Technology stack badges
stack_text = "CORE STACK: Next.js 14 App Router  •  FastAPI Python 3.11  •  Leaflet 1.9  •  Scikit-Learn NLP  •  Tailwind CSS  •  ReportLab PDF"
draw.text((100, footer_y + 35), stack_text, font=font_footer_bold, fill=(226, 232, 240))

# Bottom links & info
draw.text((100, footer_y + 105), "🔗 GitHub: https://github.com/looukyaa155-sudo/sih26106-threat-platform", font=font_footer, fill=(148, 163, 184))
draw.text((W - 1400, footer_y + 105), "⚡ Live Production Application: https://sih26106-threat-platform.vercel.app", font=font_footer, fill=(103, 232, 249))

print("Saving final high-resolution poster to disk...")
canvas = canvas.convert("RGB")
canvas.save(output_path, "PNG", quality=95)
print(f"SUCCESS! Poster saved at {output_path}")
