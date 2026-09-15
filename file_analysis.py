"""
file_analysis.py
------------------
Static, heuristic analysis of uploaded files to flag likely malicious
documents and executables. NOTHING is ever executed, opened, or run —
all analysis is byte-level inspection (file signatures, embedded
strings, zip structure, entropy). These are the same categories of
static heuristic used by real antivirus engines' first-pass scanners.

Detects:
 - Extension / true-file-type mismatches (e.g. "invoice.pdf" that is
   actually a Windows executable)
 - RTLO (right-to-left override) filename spoofing tricks
 - Double extensions ("invoice.pdf.exe")
 - Office documents with embedded macros (vbaProject.bin / VBA markers)
 - Suspicious API / command strings inside a binary (process injection,
   living-off-the-land commands, auto-download patterns)
 - Zip-bomb style compression ratios inside archive-based files
 - High-entropy (packed/encrypted) payloads
 - Suspicious filenames using phishing-style social-engineering keywords
"""

import re
import io
import math
import hashlib
import zipfile
import unicodedata

from deep_file_analysis import run_deep_analysis

# ----------------------------------------------------------------------
# Signatures
# ----------------------------------------------------------------------
MAGIC_SIGNATURES = [
    (b"\x4D\x5A", "Windows PE executable (.exe/.dll/.scr)"),
    (b"\x7fELF", "Linux ELF executable"),
    (b"\xCA\xFE\xBA\xBE", "Mach-O / Java class (macOS/Java executable)"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP-based archive (docx/xlsx/pptx/apk/jar/zip)"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Legacy Office document (doc/xls/ppt, OLE format)"),
    (b"\x89PNG", "PNG image"),
    (b"\xFF\xD8\xFF", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xBC\xAF\x27\x1C", "7-Zip archive"),
    (b"%!PS", "PostScript document"),
]

EXECUTABLE_TYPES = {
    "Windows PE executable (.exe/.dll/.scr)",
    "Linux ELF executable",
    "Mach-O / Java class (macOS/Java executable)",
}

DOCUMENT_LIKE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "rtf", "odt", "png", "jpg", "jpeg", "gif",
}

EXECUTABLE_EXTENSIONS = {
    "exe", "dll", "scr", "bat", "cmd", "com", "msi", "jar", "apk", "vbs",
    "ps1", "js", "wsf", "hta",
}

SUSPICIOUS_API_STRINGS = [
    "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
    "URLDownloadToFile", "WinExec", "ShellExecute", "GetProcAddress",
    "LoadLibraryA", "RegSetValueEx", "InternetOpenUrl", "WScript.Shell",
    "powershell -enc", "powershell.exe -nop", "Invoke-Expression",
    "IEX(", "cmd.exe /c", "certutil -decode", "AutoOpen", "Auto_Open",
    "Document_Open", "CreateObject(\"WScript.Shell\")", "bitsadmin",
    "mshta.exe", "rundll32.exe", "DownloadString",
]

MACRO_MARKERS = [b"vbaProject.bin", b"VBA", b"Attribut VB_"]

FILENAME_SOCIAL_KEYWORDS = [
    "invoice", "payment", "receipt", "statement", "urgent", "overdue",
    "refund", "confirm", "verify", "account", "salary", "bonus",
    "shipping", "delivery", "resume", "cv_", "important", "scan_",
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _detect_true_type(data: bytes) -> str:
    for sig, label in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label
    return "Unknown / unrecognized binary format"


def _has_rtlo(filename: str) -> bool:
    return any(unicodedata.category(c) == "Cf" and ord(c) in (0x202E, 0x202D) for c in filename)


def _extension_of(filename: str) -> str:
    parts = filename.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


def _double_extension(filename: str) -> bool:
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    second_last = parts[-2].lower()
    last = parts[-1].lower()
    return second_last in DOCUMENT_LIKE_EXTENSIONS and last in EXECUTABLE_EXTENSIONS


def _check_zip_structure(data: bytes):
    """Returns (is_zip_bomb, has_macro, entry_count, max_ratio)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return False, False, 0, 0.0

    has_macro = False
    max_ratio = 0.0
    entry_count = 0
    total_uncompressed = 0
    try:
        for info in zf.infolist():
            entry_count += 1
            total_uncompressed += info.file_size
            if info.compress_size > 0:
                ratio = info.file_size / max(info.compress_size, 1)
                max_ratio = max(max_ratio, ratio)
            name_lower = info.filename.lower()
            if "vbaproject.bin" in name_lower or "macros/" in name_lower:
                has_macro = True
    except Exception:
        pass

    is_bomb = max_ratio > 500 or total_uncompressed > 300 * 1024 * 1024
    return is_bomb, has_macro, entry_count, round(max_ratio, 1)


def analyze_file(data: bytes, filename: str) -> dict:
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)
    true_type = _detect_true_type(data)
    claimed_ext = _extension_of(filename)

    is_zip_based = true_type.startswith("ZIP-based")
    is_bomb, has_macro_zip, zip_entries, max_ratio = (
        _check_zip_structure(data) if is_zip_based else (False, False, 0, 0.0)
    )

    # Legacy OLE macro heuristic (old .doc/.xls binary format)
    has_macro_ole = true_type.startswith("Legacy Office") and any(
        m in data[:200000] for m in MACRO_MARKERS
    )
    has_macro = has_macro_zip or has_macro_ole

    # extension mismatch: claimed extension's expected type family vs actual
    mismatch = False
    disguised_executable = False
    if claimed_ext in DOCUMENT_LIKE_EXTENSIONS:
        if true_type in EXECUTABLE_TYPES:
            mismatch = True
            disguised_executable = True
        elif claimed_ext == "pdf" and not true_type.startswith("PDF"):
            mismatch = True
        elif claimed_ext in {"docx", "xlsx", "pptx"} and not is_zip_based:
            mismatch = True
        elif claimed_ext in {"doc", "xls", "ppt"} and not true_type.startswith("Legacy Office"):
            mismatch = True

    rtlo = _has_rtlo(filename)
    double_ext = _double_extension(filename)

    # suspicious string scan (decode leniently, cap search size for speed)
    sample = data[:2_000_000]
    text_sample = sample.decode("latin-1", errors="ignore")
    found_strings = sorted({s for s in SUSPICIOUS_API_STRINGS if s in text_sample})

    entropy = round(_shannon_entropy(sample), 3)
    high_entropy = entropy >= 7.5 and size > 5000  # near-random => likely packed/encrypted

    filename_lower = filename.lower()
    filename_flag = any(k in filename_lower for k in FILENAME_SOCIAL_KEYWORDS)

    # -------------------- weighted risk score --------------------
    score = 0
    reasons = []

    if disguised_executable:
        score += 55
        reasons.append(f"File is disguised as a '{claimed_ext}' but is actually a {true_type}")
    elif mismatch:
        score += 30
        reasons.append(f"File extension doesn't match its real format (detected: {true_type})")

    if rtlo:
        score += 30
        reasons.append("Filename uses a right-to-left override trick to hide its real extension")

    if double_ext:
        score += 22
        reasons.append("Filename uses a double extension (e.g. 'file.pdf.exe') to disguise an executable")

    if has_macro:
        score += 25
        reasons.append("Document contains embedded macros (VBA) — a common malware delivery method")

    if found_strings:
        score += min(30, 6 * len(found_strings))
        preview = ", ".join(found_strings[:5])
        reasons.append(f"Contains suspicious code strings often used by malware: {preview}")

    if high_entropy:
        score += 18
        reasons.append(f"File content has unusually high entropy ({entropy}/8) — suggests packing or encryption")

    if is_bomb:
        score += 28
        reasons.append(f"Archive has a suspicious compression ratio ({max_ratio}x) — possible zip-bomb")

    if filename_flag and (true_type in EXECUTABLE_TYPES or claimed_ext in EXECUTABLE_EXTENSIONS):
        score += 12
        reasons.append("Filename uses social-engineering wording (invoice/urgent/payment) paired with an executable")

    score = min(100, score)

    # -------------------- format-specific deep analysis --------------------
    deep_result = run_deep_analysis(data, filename, true_type)
    if deep_result:
        deep_score = deep_result["score"]
        # Combine as independent risk probabilities (1 - (1-a)(1-b)) rather
        # than a flat weighted sum, so a single strong deep-analysis signal
        # (e.g. a PDF /Launch action) isn't diluted just because the
        # general checks alone found nothing.
        base_frac = score / 100
        deep_frac = deep_score / 100
        combined_frac = 1 - (1 - base_frac) * (1 - deep_frac)
        score = min(100, round(combined_frac * 100))
        for r in deep_result["reasons"]:
            if "No known malicious" not in r and "No steganography" not in r and "No high-risk" not in r:
                reasons.append(f"[{deep_result['kind'].upper()}] {r}")

    if not reasons:
        reasons.append("No known malicious indicators found in static analysis")

    if score >= 55:
        verdict = "Malicious"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    result = {
        "filename": filename,
        "size_bytes": size,
        "sha256": sha256,
        "detected_type": true_type,
        "claimed_extension": claimed_ext or "(none)",
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "details": {
            "extension_mismatch": mismatch,
            "disguised_executable": disguised_executable,
            "rtlo_trick": rtlo,
            "double_extension": double_ext,
            "has_macro": has_macro,
            "entropy": entropy,
            "high_entropy": high_entropy,
            "suspicious_strings_found": found_strings,
            "zip_entries": zip_entries if is_zip_based else None,
            "zip_max_compression_ratio": max_ratio if is_zip_based else None,
            "zip_bomb_suspected": is_bomb,
        },
    }
    if deep_result:
        result["deep_analysis"] = {
            "kind": deep_result["kind"],
            "score": deep_result["score"],
            "details": deep_result["details"],
        }
    return result
