# VulnScout MCP

An [MCP](https://modelcontextprotocol.io) (Model Context Protocol) server that exposes [VulnScout](https://github.com/savoirfairelinux/vulnscout)'s VEX assessment and variant-context APIs as tools for LLM agents. It lets an agent read and write vulnerability assessments and variant metadata in VulnScout directly from a chat session.

## Features

- **Write VEX assessments** for a CVE across one or more packages, supporting both OpenVEX and CycloneDX VEX status/justification/response values.
- **Read assessments**, either a single assessment by ID or the full history for a given CVE.
- **Read and update variant context** (deployment environment, platform, objectives profile, notes) by variant UUID or by project/variant name.
- Thin, dependency-light implementation: a single `httpx`-based API client plus a small set of [FastMCP](https://github.com/modelcontextprotocol/python-sdk) tool modules.

## Requirements

- Python 3.9+
- A running instance of VulnScout, reachable over HTTP

## Getting started

### Run with the bootstrap launcher (recommended for MCP clients)

`run_server.py` is a self-contained launcher: on first run it creates a local `venv/`, installs `requirements.txt` into it, then execs into the server. This means an MCP client can point straight at the script without any manual setup.

Point your MCP client configuration at it, for example:

```json
{
  "mcpServers": {
    "vulnscout": {
      "command": "python3",
      "args": ["/path/to/vulnscout-mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      }
    }
  }
}
```

### Run manually

```bash
pip install -r requirements.txt
export VULNSCOUT_BASE_URL=http://localhost:7275  # optional, this is the default
python server.py
```

## Configuration

| Environment variable | Default                 | Description                          |
| --------------------- | ------------------------ | ------------------------------------ |
| `VULNSCOUT_BASE_URL`  | `http://localhost:7275` | Base URL of the VulnScout API server |

## Available tools

| Tool                          | Description                                                        |
| ------------------------------ | -------------------------------------------------------------------- |
| `write_assessment`             | Create a VEX assessment for a CVE on one or more packages           |
| `get_assessment`                | Retrieve a single VEX assessment by ID                               |
| `list_assessments_by_vuln`     | List all VEX assessments recorded for a CVE                          |
| `get_variant_context`          | Get context fields for a variant by UUID                             |
| `update_variant_context`       | Update context fields for a variant by UUID (partial updates)       |
| `get_variant_context_by_name`  | Get context fields for a variant by project name and variant name   |

> [!NOTE]
> Every tool returns a plain string: either a formatted summary of the result or an `Error: ...` message. Tools never raise exceptions back to the agent.

## Project structure

```
client.py          VulnScoutClient: httpx wrapper around the VulnScout HTTP API
server.py           Builds the FastMCP server and registers tool modules
run_server.py       Self-bootstrapping launcher (creates venv, installs deps, execs server.py)
tools/
  assessments.py    Tools for reading/writing VEX assessments
  variants.py       Tools for reading/updating variant context
tests/              pytest + respx test suite
```

## Development

Install dependencies (including test-only ones):

```bash
pip install -r requirements.txt
```

Run the test suite from the repo root:

```bash
pytest -q
```

Run a single test:

```bash
pytest tests/test_assessments.py::TestWriteAssessmentImpl::test_api_error_returns_error_string -q
```

See [`.github/copilot-instructions.md`](.github/copilot-instructions.md) for a deeper look at the architecture and codebase conventions.

## License

This project is licensed under the [GNU General Public License v3.0 only](LICENSE).
