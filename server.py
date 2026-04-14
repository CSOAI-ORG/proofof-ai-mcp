"""
ProofOf.AI MCP Server - Digital Content Verification
Built by MEOK AI Labs | https://proofof.ai

Provides AI content detection, deepfake metadata analysis,
content certificates, and C2PA provenance checking.
"""

import hashlib
import json
import math
import re
import struct
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Path traversal protection
BLOCKED_PATH_PATTERNS = ["/etc/", "/var/", "/proc/", "/sys/", "/dev/", ".."]


def _validate_file_path(file_path: str) -> str | None:
    """Validate file path against traversal attacks. Returns error message or None."""
    import os
    for pattern in BLOCKED_PATH_PATTERNS:
        if pattern in file_path:
            return f"Access denied: path contains blocked pattern '{pattern}'"
    real = os.path.realpath(file_path)
    if not os.path.isfile(real):
        return f"File not found: {file_path}"
    return None



# ── Authentication ──────────────────────────────────────────────
import os as _os
import sys, os
sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
from auth_middleware import check_access
_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

def _check_auth(api_key: str = "") -> str | None:
    """Check API key if MEOK_API_KEY is set. Returns error or None."""
    if _MEOK_API_KEY and api_key != _MEOK_API_KEY:
        return "Invalid API key. Get one at https://meok.ai/api-keys"
    return None


mcp = FastMCP(
    "proofof-ai")

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
_RATE_LIMITS = {
    "free": {"requests_per_hour": 50, "certificates_per_day": 10},
    "pro": {"requests_per_hour": 5000, "certificates_per_day": 1000},
}
_request_log: list[float] = []
_tier = "free"

# ---------------------------------------------------------------------------
# In-memory stores (swap for Redis/Postgres in production)
# ---------------------------------------------------------------------------
_certificates: dict[str, dict] = {}
_stats = {
    "total_verifications": 0,
    "text_checks": 0,
    "image_checks": 0,
    "certificates_issued": 0,
    "certificates_verified": 0,
    "provenance_checks": 0,
    "started_at": datetime.now(timezone.utc).isoformat(),
}


def _check_rate_limit() -> bool:
    """Enforce per-tier rate limits."""
    now = time.time()
    window = 3600  # 1 hour
    _request_log[:] = [t for t in _request_log if now - t < window]
    limit = _RATE_LIMITS[_tier]["requests_per_hour"]
    if len(_request_log) >= limit:
        return False
    _request_log.append(now)
    return True


# ---- Linguistic analysis helpers ------------------------------------------

_COMMON_AI_PHRASES = [
    "it's important to note",
    "it is important to note",
    "it's worth noting",
    "in conclusion",
    "delve into",
    "landscape",
    "tapestry",
    "multifaceted",
    "holistic",
    "synergy",
    "leverage",
    "paradigm",
    "robust",
    "comprehensive",
    "cutting-edge",
    "game-changer",
    "at the end of the day",
    "in today's world",
    "dive into",
    "explore the",
    "navigate the",
    "realm of",
    "in the realm",
    "it should be noted",
    "moreover",
    "furthermore",
    "additionally",
    "consequently",
    "nevertheless",
]


def _calculate_perplexity_proxy(text: str) -> float:
    """Estimate perplexity via word-frequency uniformity (proxy without a full LM).

    Lower values suggest AI text (more predictable word choice).
    """
    words = re.findall(r"[a-z]+", text.lower())
    if len(words) < 20:
        return 100.0  # too short to judge
    freq = Counter(words)
    total = len(words)
    probs = [c / total for c in freq.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    return round(entropy, 4)


def _calculate_burstiness(text: str) -> float:
    """Measure sentence-length variance.

    AI text tends to have low burstiness (uniform sentence lengths).
    Human text is more erratic.
    """
    sentences = re.split(r"[.!?]+", text)
    lengths = [len(s.split()) for s in sentences if s.strip()]
    if len(lengths) < 3:
        return 0.5
    mean = sum(lengths) / len(lengths)
    variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    std = math.sqrt(variance)
    burstiness = std / mean if mean > 0 else 0
    return round(burstiness, 4)


def _detect_repetition_patterns(text: str) -> dict:
    """Look for n-gram repetition typical of LLM output."""
    words = text.lower().split()
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words) - 1)]
    trigrams = [f"{words[i]} {words[i+1]} {words[i+2]}" for i in range(len(words) - 2)]

    bigram_counts = Counter(bigrams)
    trigram_counts = Counter(trigrams)

    repeated_bigrams = {k: v for k, v in bigram_counts.items() if v > 2}
    repeated_trigrams = {k: v for k, v in trigram_counts.items() if v > 2}

    repetition_score = (len(repeated_bigrams) * 2 + len(repeated_trigrams) * 3) / max(len(words), 1)
    return {
        "repetition_score": round(repetition_score, 4),
        "repeated_bigrams": dict(list(sorted(repeated_bigrams.items(), key=lambda x: -x[1]))[:5]),
        "repeated_trigrams": dict(list(sorted(repeated_trigrams.items(), key=lambda x: -x[1]))[:3]),
    }


def _scan_ai_phrases(text: str) -> list[str]:
    lower = text.lower()
    return [p for p in _COMMON_AI_PHRASES if p in lower]


# ---- EXIF / metadata helpers ---------------------------------------------

_AI_GENERATOR_TAGS = [
    "stable diffusion",
    "midjourney",
    "dall-e",
    "dalle",
    "comfyui",
    "automatic1111",
    "invoke ai",
    "novelai",
    "adobe firefly",
    "bing image creator",
    "leonardo.ai",
    "ideogram",
    "flux",
    "playground",
]

_AI_EXIF_MARKERS = {
    "Software": _AI_GENERATOR_TAGS,
    "ImageDescription": ["ai generated", "generated by", "created with"],
    "UserComment": _AI_GENERATOR_TAGS + ["steps:", "cfg scale", "sampler", "seed:"],
    "XMP:CreatorTool": _AI_GENERATOR_TAGS,
    "PNG:Parameters": ["steps:", "sampler:", "cfg scale", "seed:"],
}


def _parse_basic_image_metadata(data: bytes) -> dict:
    """Extract basic metadata from image bytes (PNG/JPEG headers)."""
    meta: dict = {"format": "unknown", "size_bytes": len(data)}

    if data[:8] == b"\x89PNG\r\n\x1a\n":
        meta["format"] = "PNG"
        # Parse IHDR
        if len(data) > 24:
            w = struct.unpack(">I", data[16:20])[0]
            h = struct.unpack(">I", data[20:24])[0]
            meta["width"] = w
            meta["height"] = h
        # Look for tEXt/iTXt chunks containing AI params
        text_chunks = []
        pos = 8
        while pos < len(data) - 12:
            chunk_len = struct.unpack(">I", data[pos : pos + 4])[0]
            chunk_type = data[pos + 4 : pos + 8].decode("ascii", errors="replace")
            chunk_data = data[pos + 8 : pos + 8 + chunk_len]
            if chunk_type in ("tEXt", "iTXt"):
                try:
                    text_chunks.append(chunk_data.decode("utf-8", errors="replace"))
                except Exception:
                    pass
            pos += 12 + chunk_len
        if text_chunks:
            meta["text_chunks"] = text_chunks[:10]

    elif data[:2] == b"\xff\xd8":
        meta["format"] = "JPEG"
        # Basic JPEG parsing for APP1 (EXIF)
        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
            if marker == 0xE1:  # APP1
                exif_data = data[pos + 4 : pos + 2 + seg_len]
                meta["has_exif"] = True
                try:
                    exif_str = exif_data.decode("utf-8", errors="replace")
                    meta["exif_preview"] = exif_str[:500]
                except Exception:
                    pass
            pos += 2 + seg_len
            if marker == 0xDA:  # Start of scan
                break

    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        meta["format"] = "WebP"

    return meta


# ===========================================================================
# MCP Tools
# ===========================================================================


@mcp.tool()
def verify_text_origin(text: str, api_key: str = "") -> dict:
    """Analyze text for AI-generated patterns.

    Examines perplexity, burstiness, repetition patterns and known AI phrases
    to estimate whether text was human or AI authored.

    Args:
        text: The text content to analyze (min 50 chars recommended).

    Returns:
        Confidence score, classification, and detailed analysis breakdown.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to Pro at https://proofof.ai/pricing"}

    _stats["total_verifications"] += 1
    _stats["text_checks"] += 1

    if len(text.strip()) < 20:
        return {"error": "Text too short for reliable analysis. Provide at least 50 characters."}

    entropy = _calculate_perplexity_proxy(text)
    burstiness = _calculate_burstiness(text)
    repetition = _detect_repetition_patterns(text)
    ai_phrases = _scan_ai_phrases(text)

    # Scoring rubric (0 = definitely human, 1 = definitely AI)
    scores = []

    # Entropy: AI text clusters around 4.5-6.5, human text is wider
    if entropy < 5.0:
        scores.append(0.7)
    elif entropy < 6.0:
        scores.append(0.5)
    elif entropy < 7.0:
        scores.append(0.35)
    else:
        scores.append(0.2)

    # Burstiness: AI tends to be < 0.5, humans > 0.6
    if burstiness < 0.3:
        scores.append(0.8)
    elif burstiness < 0.5:
        scores.append(0.6)
    elif burstiness < 0.7:
        scores.append(0.35)
    else:
        scores.append(0.15)

    # Repetition
    rep_score = repetition["repetition_score"]
    if rep_score > 0.05:
        scores.append(0.7)
    elif rep_score > 0.02:
        scores.append(0.5)
    else:
        scores.append(0.3)

    # AI phrase density
    phrase_density = len(ai_phrases) / max(len(text.split()), 1) * 100
    if phrase_density > 2:
        scores.append(0.85)
    elif phrase_density > 0.5:
        scores.append(0.6)
    elif len(ai_phrases) > 0:
        scores.append(0.45)
    else:
        scores.append(0.2)

    ai_confidence = round(sum(scores) / len(scores), 4)

    if ai_confidence > 0.7:
        classification = "likely_ai_generated"
    elif ai_confidence > 0.5:
        classification = "possibly_ai_generated"
    elif ai_confidence > 0.35:
        classification = "uncertain"
    else:
        classification = "likely_human"

    word_count = len(text.split())
    sentence_count = len(re.split(r"[.!?]+", text))

    return {
        "classification": classification,
        "ai_confidence": ai_confidence,
        "analysis": {
            "entropy": entropy,
            "burstiness": burstiness,
            "repetition": repetition,
            "ai_phrases_found": ai_phrases,
            "ai_phrase_count": len(ai_phrases),
        },
        "text_stats": {
            "word_count": word_count,
            "sentence_count": sentence_count,
            "avg_sentence_length": round(word_count / max(sentence_count, 1), 1),
        },
        "disclaimer": "Statistical analysis only. Not a definitive determination. "
        "Short texts (<200 words) have lower accuracy.",
        "powered_by": "proofof.ai",
    }


@mcp.tool()
def detect_deepfake_image(image_base64: Optional[str] = None, image_path: Optional[str] = None, api_key: str = "") -> dict:
    """Check image metadata for AI generation signatures.

    Performs lightweight metadata-based analysis (EXIF, PNG chunks, compression
    patterns) without requiring ML inference. Checks for known AI tool
    signatures, suspicious metadata patterns, and generation parameters.

    Args:
        image_base64: Base64-encoded image data.
        image_path: Local file path to image (alternative to base64).

    Returns:
        Detection results with metadata findings and risk assessment.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to Pro at https://proofof.ai/pricing"}

    _stats["total_verifications"] += 1
    _stats["image_checks"] += 1

    import base64

    data = None
    if image_base64:
        try:
            data = base64.b64decode(image_base64)
        except Exception:
            return {"error": "Invalid base64 data"}
    elif image_path:
        path_err = _validate_file_path(image_path)
        if path_err:
            return {"error": path_err}
        try:
            with open(image_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return {"error": f"File not found: {image_path}"}
        except Exception as e:
            return {"error": f"Could not read file: {e}"}
    else:
        return {"error": "Provide either image_base64 or image_path"}

    meta = _parse_basic_image_metadata(data)
    findings: list[str] = []
    risk_signals: list[str] = []
    risk_score = 0.0

    # Check text chunks / EXIF for AI tool signatures
    searchable_text = ""
    for chunk in meta.get("text_chunks", []):
        searchable_text += chunk.lower() + " "
    if "exif_preview" in meta:
        searchable_text += meta["exif_preview"].lower()

    for tag, markers in _AI_EXIF_MARKERS.items():
        for marker in markers:
            if marker.lower() in searchable_text:
                findings.append(f"AI signature detected: '{marker}' found in metadata")
                risk_score += 0.3

    # Check for generation parameters (steps, cfg, seed, sampler)
    gen_params = ["steps:", "cfg scale", "sampler:", "seed:", "negative prompt", "model:", "lora:"]
    found_params = [p for p in gen_params if p in searchable_text]
    if found_params:
        findings.append(f"Generation parameters found: {', '.join(found_params)}")
        risk_score += 0.25

    # Suspicious: no EXIF at all on a JPEG (stripped metadata)
    if meta["format"] == "JPEG" and not meta.get("has_exif"):
        risk_signals.append("JPEG has no EXIF data - metadata may have been stripped")
        risk_score += 0.1

    # Check for perfectly square or common AI resolutions
    w = meta.get("width", 0)
    h = meta.get("height", 0)
    ai_resolutions = [
        (512, 512), (768, 768), (1024, 1024), (1024, 1536), (1536, 1024),
        (896, 1152), (1152, 896), (2048, 2048), (1344, 768), (768, 1344),
    ]
    if (w, h) in ai_resolutions:
        risk_signals.append(f"Resolution {w}x{h} is commonly used by AI generators")
        risk_score += 0.15

    risk_score = min(round(risk_score, 2), 1.0)

    if risk_score > 0.6:
        assessment = "high_risk_ai_generated"
    elif risk_score > 0.3:
        assessment = "moderate_risk"
    elif risk_score > 0.1:
        assessment = "low_risk"
    else:
        assessment = "no_ai_indicators_found"

    return {
        "assessment": assessment,
        "risk_score": risk_score,
        "image_metadata": {
            "format": meta["format"],
            "size_bytes": meta["size_bytes"],
            "width": meta.get("width"),
            "height": meta.get("height"),
            "has_exif": meta.get("has_exif", False),
        },
        "findings": findings if findings else ["No AI generation signatures found in metadata"],
        "risk_signals": risk_signals,
        "disclaimer": "Metadata-based analysis only. Sophisticated AI images may have clean metadata. "
        "Does not perform pixel-level deepfake detection.",
        "powered_by": "proofof.ai",
    }


@mcp.tool()
def generate_content_certificate(
    content: str,
    content_type: str = "text",
    author: Optional[str] = None,
    purpose: Optional[str] = None, api_key: str = "") -> dict:
    """Create a signed verification certificate for content.

    Generates a unique certificate that records the content hash, timestamp,
    and verification analysis. Certificates can be verified later by ID.

    Args:
        content: The content to certify (text or base64 image data).
        content_type: Either "text" or "image".
        author: Optional author attribution.
        purpose: Optional purpose/context for certification.

    Returns:
        Certificate with unique ID, hash, timestamp, and analysis.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade to Pro at https://proofof.ai/pricing"}

    daily_limit = _RATE_LIMITS[_tier]["certificates_per_day"]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    today_certs = sum(1 for c in _certificates.values() if c["issued_at"].startswith(today))
    if today_certs >= daily_limit:
        return {"error": f"Daily certificate limit ({daily_limit}) reached. Upgrade to Pro."}

    cert_id = f"POA-{uuid.uuid4().hex[:12].upper()}"
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    issued_at = datetime.now(timezone.utc).isoformat()

    # Run analysis
    analysis = {}
    if content_type == "text":
        analysis = verify_text_origin(text=content)
    elif content_type == "image":
        analysis = detect_deepfake_image(image_base64=content)

    certificate = {
        "certificate_id": cert_id,
        "content_hash": content_hash,
        "content_type": content_type,
        "issued_at": issued_at,
        "author": author,
        "purpose": purpose,
        "analysis_summary": {
            "classification": analysis.get("classification", analysis.get("assessment", "unknown")),
            "confidence": analysis.get("ai_confidence", analysis.get("risk_score", None)),
        },
        "verification_url": f"https://proofof.ai/verify/{cert_id}",
        "issuer": "ProofOf.AI by MEOK AI Labs",
        "signature": hashlib.sha256(f"{cert_id}:{content_hash}:{issued_at}".encode()).hexdigest()[:32],
    }

    _certificates[cert_id] = certificate
    _stats["certificates_issued"] += 1

    return certificate


@mcp.tool()
def verify_certificate(certificate_id: str, api_key: str = "") -> dict:
    """Verify a previously generated content certificate by ID.

    Args:
        certificate_id: The certificate ID (format: POA-XXXXXXXXXXXX).

    Returns:
        Certificate details if valid, or error if not found.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    cert = _certificates.get(certificate_id)
    if not cert:
        return {
            "valid": False,
            "error": f"Certificate {certificate_id} not found. "
            "It may have expired or the ID may be incorrect.",
        }

    _stats["certificates_verified"] += 1

    # Verify signature integrity
    expected_sig = hashlib.sha256(
        f"{cert['certificate_id']}:{cert['content_hash']}:{cert['issued_at']}".encode()
    ).hexdigest()[:32]

    return {
        "valid": cert["signature"] == expected_sig,
        "certificate": cert,
        "integrity_check": "passed" if cert["signature"] == expected_sig else "FAILED - tampered",
    }


@mcp.tool()
def check_provenance(file_path: Optional[str] = None, file_base64: Optional[str] = None, api_key: str = "") -> dict:
    """Check C2PA / Content Credentials metadata in files.

    C2PA (Coalition for Content Provenance and Authenticity) embeds
    cryptographic provenance data in media files. This tool checks
    for the presence of C2PA manifests and extracts basic info.

    Args:
        file_path: Path to file to check.
        file_base64: Base64-encoded file data (alternative).

    Returns:
        Provenance information if C2PA data is found.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    _stats["provenance_checks"] += 1
    _stats["total_verifications"] += 1

    import base64

    data = None
    if file_path:
        path_err = _validate_file_path(file_path)
        if path_err:
            return {"error": path_err}
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return {"error": f"File not found: {file_path}"}
    elif file_base64:
        try:
            data = base64.b64decode(file_base64)
        except Exception:
            return {"error": "Invalid base64 data"}
    else:
        return {"error": "Provide file_path or file_base64"}

    # C2PA manifests are identified by JUMBF (JPEG Universal Metadata Box Format)
    # boxes with UUID c2pa (63327061). Also check for XMP c2pa references.
    c2pa_markers = [
        b"c2pa",
        b"C2PA",
        b"jumb",  # JUMBF box marker
        b"c2pa.assertions",
        b"c2pa.claim",
        b"contentauthenticity.org",
        b"cai:",  # Content Authenticity Initiative
    ]

    found_markers: list[str] = []
    for marker in c2pa_markers:
        if marker in data:
            found_markers.append(marker.decode("ascii", errors="replace"))

    has_c2pa = len(found_markers) > 0

    # Also check for Adobe Content Credentials XMP
    has_adobe_cr = b"stRef:originalDocumentID" in data or b"photoshop:Credit" in data

    result = {
        "has_c2pa": has_c2pa,
        "has_content_credentials": has_c2pa or has_adobe_cr,
        "markers_found": found_markers,
        "file_size_bytes": len(data),
    }

    if has_c2pa:
        result["status"] = "c2pa_manifest_detected"
        result["note"] = (
            "C2PA manifest found. For full validation (signature verification, "
            "assertion parsing), use the C2PA reference tool at https://verify.contentauthenticity.org"
        )
    elif has_adobe_cr:
        result["status"] = "adobe_content_credentials_detected"
        result["note"] = "Adobe Content Credentials metadata found (legacy format)."
    else:
        result["status"] = "no_provenance_data"
        result["note"] = "No C2PA or Content Credentials metadata found in this file."

    result["powered_by"] = "proofof.ai"
    return result


@mcp.tool()
def get_verification_stats(api_key: str = "") -> dict:
    """Return statistics on verifications performed by this server instance.

    Returns:
        Counts of verifications, certificates, and uptime info.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}
    return {
        **_stats,
        "current_tier": _tier,
        "rate_limits": _RATE_LIMITS[_tier],
        "certificates_stored": len(_certificates),
        "powered_by": "proofof.ai",
        "upgrade_url": "https://proofof.ai/pricing",
    }


if __name__ == "__main__":
    mcp.run()