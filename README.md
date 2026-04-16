# ProofOf.AI Verification MCP Server

> **By [MEOK AI Labs](https://meok.ai)** — Sovereign AI tools for everyone.

Digital content verification for the AI era. Detect AI-generated text, check images for deepfake signatures, generate signed content certificates, verify provenance via C2PA/Content Credentials, and track verification statistics.

[![MCPize](https://img.shields.io/badge/MCPize-Listed-blue)](https://mcpize.com/mcp/proofof-ai)
[![MIT License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-255+_servers-purple)](https://meok.ai)

## Tools

| Tool | Description |
|------|-------------|
| `verify_text_origin` | Analyze text for AI-generated patterns |
| `detect_deepfake_image` | Check image metadata for AI generation signatures |
| `generate_content_certificate` | Create a signed verification certificate for content |
| `verify_certificate` | Verify a previously generated content certificate |
| `check_provenance` | Check C2PA / Content Credentials metadata in files |
| `get_verification_stats` | Return statistics on verifications performed |

## Quick Start

```bash
pip install mcp
git clone https://github.com/CSOAI-ORG/proofof-ai-mcp.git
cd proofof-ai-mcp
python server.py
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "proofof-ai": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "/path/to/proofof-ai-mcp"
    }
  }
}
```

## Pricing

| Plan | Price | Requests |
|------|-------|----------|
| Free | $0/mo | 50 verifications/month |
| Pro | $19/mo | 5,000 verifications/month |

[Get on MCPize](https://mcpize.com/mcp/proofof-ai) | [Stripe](https://buy.stripe.com/bJe14p4O85km0ZT9mE8k801)

## Part of MEOK AI Labs

This is one of 255+ MCP servers by MEOK AI Labs. Browse all at [meok.ai](https://meok.ai) or [GitHub](https://github.com/CSOAI-ORG).

---

## 🏢 Enterprise & Pro Licensing

| Plan | Price | Link |
|------|-------|------|
| **ProofOf.AI MCP** | £19/mo | [Subscribe](https://buy.stripe.com/bJe14p4O85km0ZT9mE8k801) |
| **Core MCP Pack** | £49/mo | [Subscribe](https://buy.stripe.com/4gM4gB2G05kmeQJ42k8k805) |

> Part of [MEOK AI Labs](https://meok.ai) — 208+ MCP servers.

---
**MEOK AI Labs** | [meok.ai](https://meok.ai) | [csoai.org](https://csoai.org) | nicholas@meok.ai
