# ProofOf.AI MCP Server

**Digital Content Verification for the AI Era**

Built by [MEOK AI Labs](https://meok.ai) | [proofof.ai](https://proofof.ai)

---

An MCP server that provides AI content detection, deepfake metadata analysis, content certification, and C2PA provenance checking. Designed for integration into AI assistants, content platforms, and editorial workflows.

## Tools

| Tool | Description |
|------|-------------|
| `verify_text_origin` | Analyze text for AI-generated patterns (perplexity, burstiness, repetition, phrase detection) |
| `detect_deepfake_image` | Check image metadata for AI generation signatures (EXIF, PNG chunks, known tool markers) |
| `generate_content_certificate` | Create a signed verification certificate with hash, timestamp, and analysis |
| `verify_certificate` | Verify a previously issued certificate by ID |
| `check_provenance` | Check for C2PA / Content Credentials metadata in media files |
| `get_verification_stats` | Return stats on verifications performed |

## Quick Start

```bash
pip install proofof-ai-mcp
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "proofof-ai": {
      "command": "python",
      "args": ["-m", "server"],
      "cwd": "/path/to/proofof-ai-mcp"
    }
  }
}
```

### Direct Usage

```bash
python server.py
```

## Rate Limits

| Tier | Requests/Hour | Certificates/Day |
|------|--------------|-------------------|
| Free | 50 | 10 |
| Pro | 5,000 | 1,000 |

Upgrade at [proofof.ai/pricing](https://proofof.ai/pricing)

## How It Works

### Text Verification
- **Perplexity proxy**: Measures word-frequency entropy (AI text tends toward uniform distributions)
- **Burstiness analysis**: Measures sentence-length variance (AI text has low variance)
- **Repetition detection**: Scans for repeated n-grams common in LLM output
- **Phrase scanning**: Checks for known AI-favoured phrases and transitions

### Image Analysis
- Metadata-based (no ML inference required, keeps it lightweight)
- Scans EXIF, PNG tEXt/iTXt chunks for AI tool signatures
- Detects generation parameters (steps, CFG scale, sampler, seed)
- Flags common AI resolutions (512x512, 1024x1024, etc.)

### Content Certificates
- SHA-256 content hash
- Timestamped with analysis results
- Unique certificate ID for later verification
- Integrity signature to detect tampering

## License

MIT - see [LICENSE](LICENSE)

---

*Part of the MEOK AI Labs MCP Marketplace*
