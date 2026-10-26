# Seismoscope (候风)

[![CI](https://github.com/dxz0069/seismoscope/actions/workflows/ci.yml/badge.svg)](https://github.com/dxz0069/seismoscope/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/seismoscope.svg)](https://pypi.org/project/seismoscope/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)

**[中文文档](README.md)**

**Seismoscope — the security seismoscope for the AI coding era.** A security audit & verification platform for Vibe Coding workflows, embedded into AI-assisted development as a Claude Code Skill / CLI. It senses the security "tremors" in AI-generated code: deterministic multi-agent review + tri-state verification, with remediation instructions delivered straight back into your AI coding context.

Named after Zhang Heng's Houfeng Seismoscope (候风地动仪, 132 AD), the first instrument to detect earthquakes from afar — this project detects the quakes hiding in AI-generated applications before they reach production.

> Distribution name `seismoscope` (`pip install seismoscope`). Formerly known as vibe-guard / vibe-sec-platform. CLI provides both `vibe-sec` and `seismoscope` commands.

**Version**: v0.13.0 | **Status**: engineering-validation release (local single-user beta). For an honest maturity self-assessment see [docs/progress/CURRENT_PROJECT_STATUS_2026-08-01.md](docs/progress/CURRENT_PROJECT_STATUS_2026-08-01.md).

## Why

Vibe-coding ships apps in minutes — but the AI wires external pages into model context, connects user input to execution environments, and leaves tool permissions wide open. Pages, prompts, tools and permissions form a **compound runtime surface** that traditional scanners cannot see. Meanwhile, switching to a scanner breaks the conversational workflow that makes vibe coding productive.

Industry evidence: [Escape.tech scanned 5,600 vibe-coded apps and found 2,000+ vulnerabilities and 400+ exposed secrets](https://www.ox.security/blog/vibe-coding-security); the [CSA confirmed 74 AI-linked CVEs and design flaws in 45% of AI-generated solutions](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-codegen-vulnerability-debt-20260406-csa).

## Core Design

**1. Deterministic orchestration.** A fixed 12-phase pipeline (`Recon → Surface → Audit (parallel lanes) → Merge → Verify → Remediate → Retest`). The LLM never decides phase transitions; it reads code and gathers evidence through 16+ read-only tools, constrained by a reasoning guard that rejects "I think it's safe" without evidence.

**2. VRTM compound runtime surface modeling.** A four-plane directed graph (data · instruction · permission · artifact) that puts code, prompts, tools, permissions and external resources on one attack-surface map, with risk chains explaining each finding from entry point to impact.

**3. Tri-state verification.** Every risk must pass: *vulnerable-state* (the risk is reachable), *fixed-state* (the malicious path is blocked), *legitimate-control state* (normal behavior preserved). When evidence is insufficient the conclusion stays `needs_evidence` — the LLM can gather evidence but never silently dismiss a finding.

**4. Remediation bundles, not PDFs.** Confirmed risks become RemediationBundles — file/line-precise fix instructions, forbidden changes, acceptance criteria and a retest plan — consumable directly by AI coding agents, or shipped as a GitHub PR with one command.

## Quick Start

```bash
pip install seismoscope          # Python >= 3.11
seismoscope audit /path/to/project --format sarif -o results.sarif
```

Offline/restricted networks: set `VIBE_SEC_TREE_SITTER_CACHE` to a pre-seeded parser cache, or `VIBE_SEC_DISABLE_TREE_SITTER=1` to skip AST lanes (platform degrades gracefully to text analysis).

### GitHub Code Scanning

Upload results as native code-scanning alerts (example workflow: [docs/examples/seismoscope-code-scanning.yml](docs/examples/seismoscope-code-scanning.yml)):

```yaml
- run: |
    pip install seismoscope
    seismoscope audit . --format sarif -o seismoscope.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: seismoscope.sarif }
```

### Remediation PRs

```bash
seismoscope audit . --format json -o results.json
python scripts/open_remediation_pr.py results.json --repo owner/name   # one PR with all fix instructions
python scripts/open_remediation_pr.py results.json --split            # one PR per finding
```

### Skill / Docker / API

- Claude Code Skill: `scripts/install-agent-skill.ps1 -Agent claude-code` (or `sh scripts/install-agent-skill.sh claude-code`)
- Docker one-click: `sh scripts/deploy.sh --build --detach` → `http://localhost:8000`
- Deterministic setup & health checks: `vibe-sec setup` / `vibe-sec doctor --json` (reports readiness, never reads or prints key values)

Full docs: [docs/README.md](docs/README.md) (architecture, VRTM method, API, deployment, plugin development).

## Benchmarks

`scripts/benchmark_recall.py` measures deterministic (no-LLM) audit capability with recall/false-positive gates:

```bash
python scripts/benchmark_recall.py --json baseline.json     # run the four built-in fixture sets
python scripts/benchmark_recall.py --compare baseline.json  # exit 1 on recall regression or new FPs
python scripts/benchmark_recall.py --project /path/to/VAmPI --label vampi --expect sql_injection,api_key
```

Current baseline: **100% recall on all built-in fixture sets, zero false positives on the safe fixture**. A real-CVE replay baseline (`tests/test_cve_replay.py`) additionally pins line-level hits on mistune (CWE-22) and launch-editor (CWE-78); serialize-javascript's escaping-semantic bypass stays xfail — statically invisible by design, owned by the LLM semantic lane. On the real [VAmPI](https://github.com/erev0s/VAmPI) benchmark (11 Python files), all 4 statically-mappable vulnerability types are detected with zero false positives; semantic types (IDOR, debug-endpoint exposure) are the LLM lane's responsibility. CI re-runs the gate on every PR.

## Audit Scope

- Traditional web vulnerabilities: SQL injection, XSS, command/code injection, path traversal, SSRF, unsafe deserialization, secrets
- Agent-era vulnerabilities: prompt injection, MCP tool poisoning / excessive permissions, excessive agency, workflow injection
- Every finding carries CWE / OWASP identifiers ([core/audit/standards_map.py](core/audit/standards_map.py))

## License & Security

MIT License. Found a vulnerability in Seismoscope itself? Please use private GitHub vulnerability reporting — see [SECURITY.md](SECURITY.md). When auditing untrusted source, run the tool inside a container/VM.

## Links

- Repository: https://github.com/dxz0069/seismoscope
- PyPI: https://pypi.org/project/seismoscope/
- Releases & changelog: [CHANGELOG.md](CHANGELOG.md)
