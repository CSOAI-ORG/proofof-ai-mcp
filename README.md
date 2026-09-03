<!-- mcp-name: CSOAI-ORG/proofof-ai-mcp -->
[![MCP Scorecard: 86/100](https://img.shields.io/badge/proofof.ai-86%2F100-5b21b6)](https://proofof.ai/scorecard/proofof-ai-mcp.html)

# Proofof Ai MCP

> **⚖️ Built by [MEOK AI Labs](https://meok.ai) / [CSOAI](https://csoai.org).** Need this applied to _your_ system fast? Book a 30-min Founder Office Hour (£29) → **https://meok.ai/work** · Full governance platform → **https://meok.ai**

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![GSPC](https://img.shields.io/badge/GSPC-UNMEASURED-9ca3af)](https://councilof.ai/api/gspc)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/proofof_ai_mcp/)

> AI content verification & deepfake detection MCP — media forensics, synthetic media detection, pr...
<div align="center">

# ProofOf AI MCP

**AI Content Verification & Authenticity — Detect Deepfakes, Verify Origins, Certify Content**

[![MCP](https://img.shields.io/badge/MCP-Server-blue)](https://github.com/CSOAI-ORG)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
</div>

AI content verification & deepfake detection MCP — media forensics, synthetic media detection, provenance chains. MIT.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install proofof_ai_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install proofof-ai-mcp --client claude
```

## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/proofof-ai-mcp)
- [API Reference](https://api.meok.ai)
- [EU AI Act Compliance Guide](https://councilof.ai/compliance)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](https://cal.com/csoai/august-audit)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** $99/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** $499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/pricing) | [Contact Sales →](mailto:sales@csoai.org)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 300+ MCP servers for sovereign AI governance.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>
AI-powered content verification for the age of synthetic media. Detect AI-generated text, identify deepfake images, verify content origins, and generate verifiable content certificates with C2PA-compliant provenance chains.

## Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `verify_text_origin` | Check if text was AI-generated | `text` (str, required) |
| `detect_deepfake_image` | Analyze image for AI generation artifacts | `image_url` (str, required) |
| `generate_content_certificate` | Create a verifiable content certificate | `content_hash`, `author`, `timestamp` |
| `verify_certificate` | Verify a content certificate's authenticity | `certificate_id` (str, required) |
| `provenance_chain` | Trace the full provenance chain of content | `content_id` (str, required) |
| `check_manipulation` | Detect signs of manipulation in media | `media_url` (str, required) |

## Installation

```bash
pip install mcp
```

### Claude Desktop
```json
{
  "mcpServers": {
    "proofof-ai": {
      "command": "python",
      "args": ["path/to/server.py"]
    }
  }
}
```

### Cursor / VS Code / Windsurf
```json
{
  "mcpServers": {
    "proofof-ai": {
      "command": "python",
      "args": ["path/to/server.py"]
    }
  }
}
```

## Usage Examples

### Verify text origin
```json
{
  "text": "The quick brown fox jumps over the lazy dog. Studies indicate that AI-generated text often exhibits specific statistical patterns in word choice and sentence structure."
}
```

### Detect deepfake image
```json
{
  "image_url": "https://example.com/suspicious-image.jpg"
}
```

## Pricing

- **Free:** 10 verifications/day
- **Pro:** $99/mo — 500 verifications + certificates
- **Enterprise:** $499/mo — API access + custom models

---

*Built by MEOK AI Labs | [meok.ai](https://meok.ai)*

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/aFa7sNcgAdQS0ZT1Uc8k91t> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->

