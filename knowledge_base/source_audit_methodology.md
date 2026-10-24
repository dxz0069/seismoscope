# Evidence-Driven Source Audit Method

This method guides investigation. It is not project evidence and cannot confirm a finding.

## 1. Establish Coverage Before Depth

- Inventory first-party modules, entry points, background jobs, workflow files, deployment files, and dependency manifests.
- Record excluded paths and tool limits. A sampled repository is not a fully audited repository.
- Separate generated/dependency code from code owned by the project.

## 2. Form a Testable Security Path

For each candidate, identify:

1. source: attacker-controlled input, external content, event, resource, or configuration;
2. transformations: parsing, normalization, encoding, validation, and type conversion;
3. trust crossings: API, process, model, tool, MCP, filesystem, network, or tenant boundary;
4. guard: authentication, authorization, allowlist, approval, sandbox, or output encoding;
5. sink: query, shell, parser, browser, file, network, privileged tool, or sensitive asset;
6. impact and required preconditions.

Use semantic call-path evidence where the language is supported. Search text can locate a lead but does not prove reachability.

## 3. Verify Controls, Not Their Names

- Read the guard implementation and all relevant call sites.
- Check default and failure behavior, alternate entry points, encoding/canonicalization order, redirects, aliases, and asynchronous paths.
- Treat a nearby validator as irrelevant until the traced path proves it runs before the sink.
- Look for contradictory evidence and safe call sites before finalizing.

## 4. Finding Evidence Minimum

A path-dependent confirmed finding requires:

- a real source location;
- a real sink or privileged operation;
- a bounded source-to-sink/capability path;
- guard observations or an explicit statement that no guard was found in the examined path;
- artifact and tool-execution provenance;
- no unresolved evidence gap required for the claimed verdict.

Configuration defects and hardcoded credentials may be independently confirmable when the exact unsafe value or policy is parsed from a bound project location. Exploitability still requires separate validation when impact depends on runtime state.

## 5. Coverage Record

Record files planned, files examined, semantic traces, entry points, hypotheses, dependency manifests, knowledge documents loaded, unsupported languages/frameworks, truncated tools, and remaining gaps.
