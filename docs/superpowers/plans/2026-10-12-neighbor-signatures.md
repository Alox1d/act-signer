# Neighbor Signatures Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task. Steps use checkbox syntax for tracking.

**Goal:** Allow a separate own signature beside identified foreign signatures while preventing confirmed duplicates and unsafe automatic signing.

**Architecture:** Keep CScript/CAdESCOM for certificate selection, signing and full verification of new signatures. Add a read-only Windows CryptoAPI inspector inside the existing crypto module. Resolve all CMS SignerInfo certificates independently of trust, then verify each signature against exact PDF bytes with CryptVerifyDetachedMessageSignature. Keep identity, mathematical status and certificate validation distinct.

**Tech Stack:** Windows PowerShell 5.1, C# P/Invoke to crypt32.dll, JScript/CAdESCOM, existing dependency-free tests and GitHub Actions.

**Spec:** docs/neighbor-signature-spec.md

## Global Constraints

- No CryptoPro installation or system-date change on the host.
- Preserve original PDF and foreign SIG bytes, settings, adjacent output and no-overwrite behavior.
- Keep full selected-certificate and newly created signature validation.
- No unsupported Verify flags or fourth VerifyCades argument.
- Only synthetic data may enter Git, README, fixtures or CI artifacts.
- Release only after real installed CryptoPro/GOST verification; use the existing workflow and an unused patch version.

## Review Focus

- Multiple SignerInfo entries, missing certificates and ambiguous signer identifiers must not become absence.
- Unrelated chain certificates must not count as signers.
- A selected certificate with unresolved mathematical verification must block that act.
- Late document/signature changes must still block private-key use and publication.
- Document failures must continue; cancellation and unusable shared sessions must stop with explicit reasons.

### Task 1: Read-only CMS inspection

**Files:** Modify ActSigner.CryptoPro.psm1; add ActSigner.Cms.Tests.ps1.

**Interfaces:** Get-ActExistingSignatureInfo(PdfBytes, SignatureBytes) retains encoding and size guards and returns a complete signer list with per-signer Thumbprint, SignatureStatus and safe diagnostic details. Overall identity failure returns unverifiable without claiming absent signers. Certificate trust is explicitly unchecked unless a separate full check confirms it.

- [x] Write synthetic native tests for untrusted/expired RSA CMS, exact and changed bytes, damaged CMS, multiple signers, missing and ambiguous signer certificates, and extra nonsigner certificates. Confirm failure before implementation.
- [x] Implement bounded native decode, detached-content guards and unique certificate association from real SignerInfo. Verify every signer index using CryptVerifyDetachedMessageSignature; check returned signer certificate against the resolved certificate and free native handles and contexts.
- [x] Run native tests and existing crypto transport tests. Preserve CAdESCOM signing and new-signature verification behavior.

### Task 2: Duplicate policy and independent documents

**Files:** Modify ActSigner.Core.psm1, ActSigner.Core.Tests.ps1, ActSigner.CryptoPro.psm1 and Sign-Acts.Tests.ps1.

**Interfaces:** Get-ActNeighborSignatureCheck consumes complete signer identities and per-signer mathematical results. Invoke-ActBatch reports foreign signatures, already_signed and unresolved documents separately. A confirmed selected-certificate signature skips key access. Typed cancellation/session errors stop the batch; per-document errors continue.

- [x] Add failing tests for foreign expired chains, selected signer in every position, unresolved selected signer, unknown signer composition, later independent acts, cancellation/session failure and existing source/signature race protections.
- [x] Implement signer-aware policy, retain final hash/manifest checks and no-overwrite rules, and classify stopping failures explicitly.
- [x] Run Core and entry-point tests, including a repeat that creates no signature and invokes no private key.

### Task 3: UI, documentation and real validation

**Files:** Modify ActSigner.UI.psm1, Sign-Acts.ps1, related tests, README.md and README.txt. Add only synthetic CMS test invocation to .github/workflows/update-release.yml.

- [x] Verify user-facing messages distinguish foreign signatures, confirmed own signatures and uncertainty, without calling old foreign signatures fully valid.
- [x] On the actual CryptoPro Windows, reproduce the old failure on private local copies. Record OS time, process bits, CSP/CAdESCOM versions and per-element chain expiry findings outside Git.
- [x] Verify GOST math on old employer SIG, own SIG, changed PDF, corrupt SIG and multiple signers. Sign a separate problematic-act copy, fully verify it, repeat, and compare original/copy PDF and employer SIG hashes.
- [x] Run the complete existing native test suite and package contracts. Audit the Git diff for private data.

User-approved addition to Task 3: add persistent signer filename format, default
signature_<surname>.sig, plus document+surname and legacy alternatives. Verify
surname extraction, safe labels, collisions, settings and actual selected certificate.

### Task 4: Patch release

**Files:** Modify ActSigner.Version.json and release notes in existing documentation.

- [ ] Recheck GitHub state and select the next unused patch version, expected 1.5.1.
- [ ] Commit only reviewed source, synthetic tests and documentation. Push through the existing main workflow after all real checks pass.
- [ ] Verify successful workflow, new immutable release assets and updater download. Report precisely what was tested and any outstanding limitation.
