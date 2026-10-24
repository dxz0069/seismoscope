# Focused Security Tool Image

This image is an optional execution environment for deterministic scanners. It does not run the Vibe Sec Agent and does not implement a separate Worker or dispatcher protocol.

Build it from the repository root:

```text
docker build -t vibe-sec-tools:latest container/security-tools
```

The image uses a pinned Gitleaks stage from Docker Hub and copies only the
binary into the final Python/Semgrep image. Semgrep runs as the container's
unprivileged user with `HOME=/tmp`; its settings therefore stay in the bounded
tmpfs while the root filesystem and project mount remain read-only.

The Tool Gateway starts the image with a read-only project mount, no network, a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, and CPU, memory, PID, timeout, and output limits.

The initial image contains:

- Semgrep with versioned local rule packs;
- Gitleaks;
- Bandit;
- Trivy CLI (offline scans require a pre-populated, versioned database profile);
- no Kali distribution or general-purpose Agent shell.

CodeQL and Nuclei use optional dedicated images (`vibe-sec-codeql` and
`vibe-sec-nuclei`). Nuclei is not registered by the default scanner profile;
the trusted control plane must register it with an authorized target allowlist.
