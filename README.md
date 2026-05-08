<div align="center">

# Proofof Ai MCP

**ProofOf.AI MCP Server - Digital Content Verification**

[![PyPI](https://img.shields.io/pypi/v/meok-proofof-ai-mcp)](https://pypi.org/project/meok-proofof-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

ProofOf.AI MCP Server - Digital Content Verification
Built by MEOK AI Labs | https://proofof.ai

Provides AI content detection, deepfake metadata analysis,
content certificates, and C2PA provenance checking.

## Tools

| Tool | Description |
|------|-------------|
| `verify_text_origin` | Analyze text for AI-generated patterns. |
| `detect_deepfake_image` | Check image metadata for AI generation signatures. |
| `generate_content_certificate` | Create a signed verification certificate for content. |
| `verify_certificate` | Verify a previously generated content certificate by ID. |
| `check_provenance` | Check C2PA / Content Credentials metadata in files. |
| `get_verification_stats` | Return statistics on verifications performed by this server instance. |

## Installation

```bash
pip install meok-proofof-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "proofof-ai": {
      "command": "python",
      "args": ["-m", "meok_proofof_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 6 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
