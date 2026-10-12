# ActSigner startup update implementation plan

> For agentic workers: implement the assigned component and tests, then return evidence for integration review. Shared files have explicit owners.

**Goal:** Stage verified GitHub releases in the background and use the prepared version on the next startup.

**Architecture:** A bundled local launcher chooses a verified version and starts the app without network waiting. An independent hidden updater installs a complete version and atomically publishes its selection. GitHub Actions publishes explicit release assets only after Windows verification.

**Tech Stack:** Windows PowerShell 5.1, .NET Framework, Windows Forms, GitHub Releases and Actions. No installed Git, administrator access, external packages or user credentials required.

**Spec:** [auto-update-design.md](auto-update-design.md)

## Global constraints

- Version 1.5.0, launcher protocol 1, public repository Alox1d/act-signer.
- Preserve existing signing behavior and settings independently of the updater.
- No private documents, signatures, keys, certificate identities or personal diagnostics in source, tests, artifacts or releases.
- PowerShell source: UTF-8 BOM and CRLF; CMD: ASCII and CRLF; JSON/Markdown/YAML: UTF-8 LF.

## Review focus

- A prepared update must never change the version used by the current signing invocation.
- Hostile or malformed archive names must never escape staging.
- Interrupted or concurrent installations must retain a usable launch target.
- Hidden networking must never prompt or hold up foreground startup.
- A downloaded updater is not loaded before bundled verification succeeds.

## Task 1: Local selection and updater transaction

**Owner:** updater implementer. **Files:** `ActSigner.Update.psm1`, `ActSigner.Update.Tests.ps1`.

- [ ] Write failing tests for public interfaces and real synthetic ZIP activation, then observe the missing-feature failure.
- [ ] Implement strict release/manifest validation, local selection, locked staging, file verification, atomic active/previous state and bounded HTTPS downloads from the spec.
- [ ] Prove rejection and fallback behavior for version, hash, archive traversal/duplicates/ADS/links/bounds, corrupted state, parallel lock and offline providers.
- [ ] Run the updater suite under the available PowerShell runtime; preserve evidence for native Windows verification.

## Task 2: Release packaging and native workflow

**Owner:** packaging implementer. **Files:** `tools/Build-Release.ps1`, `tools/Build-Release.Tests.ps1`, `tools/Publish-Release.ps1`, `.github/workflows/update-release.yml`.

- [ ] Write a real package test asserting explicit payload entries, manifest/version/hash agreement and exclusion of injected synthetic private files.
- [ ] Implement allowlist packaging using the spec's exact asset names and manifest shape; make the test pass.
- [ ] Implement release publication as a complete draft asset pair followed by stable publication, refusing to overwrite published versions.
- [ ] Add a native Windows workflow on main and ui-layout-check that tests updater, launcher, package and existing Core/CryptoPro/entry/console/UI behavior; publication occurs only on main after all local gates succeed.

## Task 3: Startup integration and documentation

**Owner:** root. **Files:** `Start.cmd`, `Start-ActSigner.ps1`, `Update-ActSigner.ps1`, `Start-ActSigner.Tests.ps1`, `ActSigner.Version.json`, `Sign-Acts.ps1`, `ActSigner.UI.psm1`, `README.md`, `README.txt`, `.gitignore`.

- [ ] Test actual launcher subprocess selection, failure fallback, STA/exit behavior, no-update/previous switches, and paths containing Cyrillic and metacharacters.
- [ ] Implement native startup selection and noninteractive worker launch using the component interfaces, without any foreground HTTP call.
- [ ] Set the displayed version to 1.5 and explain automatic next-launch activation, offline fallback, release integrity limits and manual rollback.
- [ ] Review integrated changes; publish candidate to test branch, verify native Windows evidence, publish identical tested source to main and verify release assets.

User's subsequent supplied signature pair is diagnosed read-only in parallel. Any proven defect requiring a behavior change gets its own minimal regression test before integration.
