"""
deep_file_analysis.py
------------------------
Format-specific deep analysis, layered on top of the general checks in
file_analysis.py. All analysis is static (byte/structure inspection) —
nothing is ever rendered, opened, or executed.

 - PDF: embedded JavaScript, auto-run actions, launch actions, embedded
   files, encryption, and listed URI targets (scored with the URL model)
 - Images (PNG/JPEG): trailing data appended after the image's official
   end marker (a common simple steganography / data-hiding trick), plus
   an LSB (least-significant-bit) randomness check as a secondary signal
 - APK: permissions extracted heuristically from the binary
   AndroidManifest.xml string pool, with special attention to
   dangerous-permission combinations associated with banking trojans /
   spyware (SMS interception + accessibility service + install-package,
   etc.)
"""

import re
import io
import math
import zipfile

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


# ======================================================================
# PDF deep analysis
# ======================================================================
PDF_JS_MARKERS = [b"/JavaScript", b"/JS "]
PDF_AUTOACTION_MARKERS = [b"/OpenAction", b"/AA"]
PDF_LAUNCH_MARKERS = [b"/Launch"]
PDF_EMBEDDED_FILE_MARKERS = [b"/EmbeddedFile", b"/Filespec"]
PDF_ENCRYPT_MARKERS = [b"/Encrypt"]
PDF_URI_RE = re.compile(rb"/URI\s*\(([^)]+)\)")
PDF_FILTER_RE = re.compile(rb"/Filter\s*\[([^\]]+)\]")


def analyze_pdf(data: bytes) -> dict:
    findings = {
        "has_javascript": any(m in data for m in PDF_JS_MARKERS),
        "has_auto_action": any(m in data for m in PDF_AUTOACTION_MARKERS),
        "has_launch_action": any(m in data for m in PDF_LAUNCH_MARKERS),
        "has_embedded_file": any(m in data for m in PDF_EMBEDDED_FILE_MARKERS),
        "is_encrypted": any(m in data for m in PDF_ENCRYPT_MARKERS),
        "uris": [],
        "stacked_filters": False,
    }

    uris = PDF_URI_RE.findall(data)
    findings["uris"] = list(dict.fromkeys(
        u.decode("latin-1", errors="ignore") for u in uris
    ))[:15]

    # Stacked/chained filters (e.g. ASCIIHex + Flate + RunLength together)
    # can be a mild obfuscation signal when combined with JS.
    filter_matches = PDF_FILTER_RE.findall(data)
    findings["stacked_filters"] = any(m.count(b"/") >= 3 for m in filter_matches)

    score = 0
    reasons = []

    if findings["has_javascript"]:
        score += 35
        reasons.append("PDF contains embedded JavaScript — a common exploit/malware delivery mechanism")
    if findings["has_auto_action"]:
        score += 25
        reasons.append("PDF has an auto-run action (OpenAction/AA) that fires as soon as the file is opened")
    if findings["has_launch_action"]:
        score += 40
        reasons.append("PDF contains a /Launch action, which can run an external program on open")
    if findings["has_embedded_file"]:
        score += 20
        reasons.append("PDF has an embedded file attachment hidden inside it")
    if findings["is_encrypted"]:
        score += 10
        reasons.append("PDF is encrypted, which can be used to hide malicious content from scanners")
    if findings["stacked_filters"] and findings["has_javascript"]:
        score += 15
        reasons.append("PDF stacks multiple encoding filters alongside JavaScript — a common obfuscation pattern")
    if findings["uris"]:
        reasons.append(f"PDF contains {len(findings['uris'])} embedded link target(s) — check them in the URL scanner")

    if not reasons:
        reasons.append("No known malicious indicators found in PDF structure")

    return {"score": min(100, score), "reasons": reasons, "details": findings}


# ======================================================================
# Image steganography heuristics
# ======================================================================
PNG_IEND = b"IEND\xae\x42\x60\x82"
JPEG_EOI = b"\xff\xd9"


def _shannon_entropy_bits(bits: list) -> float:
    if not bits:
        return 0.0
    ones = sum(bits)
    n = len(bits)
    p1 = ones / n
    p0 = 1 - p1
    ent = 0.0
    for p in (p0, p1):
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def analyze_image(data: bytes, filename: str) -> dict:
    reasons = []
    score = 0
    details = {"trailing_bytes": 0, "lsb_entropy": None}

    # --- trailing data after the official end-of-image marker ---
    trailing = 0
    if data.startswith(b"\x89PNG"):
        idx = data.rfind(PNG_IEND)
        if idx != -1:
            trailing = len(data) - (idx + len(PNG_IEND))
    elif data.startswith(b"\xff\xd8\xff"):
        idx = data.rfind(JPEG_EOI)
        if idx != -1:
            trailing = len(data) - (idx + len(JPEG_EOI))

    details["trailing_bytes"] = trailing
    if trailing > 64:  # a little padding is normal; large trailing chunks are not
        score += 35
        reasons.append(
            f"Image has {trailing} bytes of data appended after its official end marker — "
            f"a common way to hide a payload inside an innocent-looking picture"
        )

    # --- LSB randomness check (secondary signal, needs Pillow) ---
    if _PIL_AVAILABLE:
        try:
            img = Image.open(io.BytesIO(data))
            img = img.convert("RGB")
            img.thumbnail((256, 256))  # cap cost
            pixels = list(img.getdata())
            lsb_bits = []
            for px in pixels[:20000]:
                for channel in px:
                    lsb_bits.append(channel & 1)
            entropy = _shannon_entropy_bits(lsb_bits)
            details["lsb_entropy"] = round(entropy, 4)
            # Near-perfect randomness (entropy ~1.0) across the whole image's
            # LSBs is unusual for natural photos and is the classic fingerprint
            # of LSB-embedded steganographic payloads.
            if entropy >= 0.997:
                score += 20
                reasons.append(
                    "Pixel least-significant-bits are almost perfectly random "
                    f"(entropy {details['lsb_entropy']}/1.0) — possible LSB steganography"
                )
        except Exception:
            pass

    score = min(100, score)
    if not reasons:
        reasons.append("No steganography indicators found")

    return {"score": score, "reasons": reasons, "details": details}


# ======================================================================
# APK permission analysis
# ======================================================================
DANGEROUS_PERMISSIONS = [
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.INTERCEPT_SMS",
    "android.permission.CALL_PHONE", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.ACCESS_FINE_LOCATION",
]

# Combinations strongly associated with banking-trojan / spyware behavior
HIGH_RISK_COMBOS = [
    ({"android.permission.RECEIVE_SMS", "android.permission.READ_SMS"},
     "Reads incoming SMS — can intercept bank OTP/2FA codes"),
    ({"android.permission.BIND_ACCESSIBILITY_SERVICE"},
     "Requests Accessibility Service access — can read screen content and simulate taps (common overlay-attack technique)"),
    ({"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"},
     "Combines draw-over-other-apps with Accessibility access — classic banking-trojan overlay pattern"),
    ({"android.permission.REQUEST_INSTALL_PACKAGES"},
     "Can silently prompt installation of additional APKs (dropper behavior)"),
    ({"android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.SYSTEM_ALERT_WINDOW"},
     "Persists across reboots and can draw overlays — used to maintain persistence and phish credentials"),
]


def analyze_apk(data: bytes) -> dict:
    reasons = []
    score = 0
    found_permissions = set()
    has_manifest = False
    dex_count = 0

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        has_manifest = "AndroidManifest.xml" in names
        dex_count = sum(1 for n in names if n.endswith(".dex"))

        if has_manifest:
            manifest_bytes = zf.read("AndroidManifest.xml")
            # Binary AXML stores its string pool largely as UTF-16LE text;
            # decoding leniently and substring-matching known permission
            # strings is a lightweight heuristic that avoids needing a full
            # binary-XML parser.
            decoded = manifest_bytes.decode("utf-16-le", errors="ignore")
            decoded += manifest_bytes.decode("latin-1", errors="ignore")
            for perm in DANGEROUS_PERMISSIONS:
                if perm in decoded:
                    found_permissions.add(perm)
    except Exception:
        return {
            "score": 0, "reasons": ["Could not parse as a valid APK/ZIP archive"],
            "details": {"permissions_found": [], "has_manifest": False, "dex_count": 0},
        }

    for combo, msg in HIGH_RISK_COMBOS:
        if combo.issubset(found_permissions):
            score += 30
            reasons.append(msg)

    other_dangerous = found_permissions - {p for combo, _ in HIGH_RISK_COMBOS for p in combo}
    if other_dangerous:
        score += min(20, 5 * len(other_dangerous))
        reasons.append(
            f"Requests {len(other_dangerous)} additional sensitive permission(s): "
            f"{', '.join(sorted(p.split('.')[-1] for p in other_dangerous))}"
        )

    if dex_count > 1:
        score += 5
        reasons.append(f"Contains {dex_count} .dex files (multidex — usually benign, but worth noting)")

    if not has_manifest:
        score += 15
        reasons.append("No AndroidManifest.xml found — not a well-formed APK, or manifest was stripped")

    score = min(100, score)
    if not reasons:
        reasons.append("No high-risk permissions detected")

    return {
        "score": score,
        "reasons": reasons,
        "details": {
            "permissions_found": sorted(found_permissions),
            "has_manifest": has_manifest,
            "dex_count": dex_count,
        },
    }


# ======================================================================
# Dispatcher
# ======================================================================
def run_deep_analysis(data: bytes, filename: str, true_type: str) -> dict:
    """Returns None if no deep analysis applies to this file type."""
    filename_lower = filename.lower()

    if true_type.startswith("PDF") or filename_lower.endswith(".pdf"):
        result = analyze_pdf(data)
        return {"kind": "pdf", **result}

    if (true_type in ("PNG image", "JPEG image")) or filename_lower.endswith((".png", ".jpg", ".jpeg")):
        result = analyze_image(data, filename)
        return {"kind": "image", **result}

    if filename_lower.endswith(".apk") or (
        true_type.startswith("ZIP-based") and filename_lower.endswith(".apk")
    ):
        result = analyze_apk(data)
        return {"kind": "apk", **result}

    return None
