#!/usr/bin/env python3
import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
_shared_auth = os.path.expanduser("~/clawd/meok-labs-engine/shared")
if os.path.isdir(_shared_auth):
    sys.path.insert(0, _shared_auth)


import server

# Bypass shared auth rate limiting for tests
server.check_access = lambda api_key="": (True, "test", "pro")


def test_server_module_imports():
    assert server is not None


def test_mcp_object_exists():
    import server
    assert hasattr(server, "mcp")


def test_tools_registered():
    import server
    expected = [
        "verify_text_origin",
        "detect_deepfake_image",
        "generate_content_certificate",
        "verify_certificate",
        "check_provenance",
        "get_verification_stats",
    ]
    for name in expected:
        assert hasattr(server, name), f"Missing tool: {name}"
        assert callable(getattr(server, name))


def test_main_function():
    import server
    assert hasattr(server, "main")
    assert callable(server.main)


def test_verify_text_origin():
    import server
    result = server.verify_text_origin(
        text="The quick brown fox jumps over the lazy dog. "
        "This sentence contains enough words for a reliable analysis. "
        "We need at least twenty words here to pass the minimum threshold."
    )
    assert isinstance(result, dict)
    assert "classification" in result
    assert result["classification"] in (
        "likely_ai_generated", "possibly_ai_generated", "uncertain", "likely_human"
    )
    assert "ai_confidence" in result
    assert "analysis" in result


def test_verify_text_origin_too_short():
    import server
    result = server.verify_text_origin(text="Short text.")
    assert isinstance(result, dict)
    assert "error" in result


def test_detect_deepfake_no_input():
    import server
    result = server.detect_deepfake_image()
    assert isinstance(result, dict)
    assert "error" in result


def test_detect_deepfake_invalid_base64():
    import server
    result = server.detect_deepfake_image(image_base64="not-valid-base64!!")
    assert isinstance(result, dict)
    assert "error" in result


def test_generate_content_certificate():
    import server
    result = server.generate_content_certificate(
        content="Test content for certification",
        content_type="text",
    )
    assert isinstance(result, dict)
    assert "certificate_id" in result or "error" in result


def test_verify_certificate_not_found():
    import server
    result = server.verify_certificate(certificate_id="POA-NONEXISTENT")
    assert isinstance(result, dict)
    assert "valid" in result or "error" in result


def test_check_provenance_no_input():
    import server
    result = server.check_provenance()
    assert isinstance(result, dict)
    assert "error" in result


def test_get_verification_stats():
    import server
    result = server.get_verification_stats()
    assert isinstance(result, dict)
    assert "total_verifications" in result
    assert "powered_by" in result
