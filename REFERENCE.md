# CSPSigner technical reference

[Russian README](README.md) | [English README](README.en.md)

This reference describes current implementation details. Start with the README for installation and everyday use.

## File discovery

The UI uses `Get-ActPlan -AllFiles` for unrestricted content formats. Folder discovery in the UI is recursive. The plan API supports `-Recurse:$false`. Signature sidecars (`.sig`, `.p7s`, `.p7m`, `.sgn`), `.tmp`, `_CSPSigner_logs`, `_ActSigner_logs` and a nested output subtree are excluded. The file picker supplies explicit `SourceFiles`; these are normalized, deduplicated and must be inside `Root`. Explicit selection permits files excluded from folder discovery. Unselected files are never signed.

The plan is sorted by relative path. Reparse points, including symbolic links and junctions, are skipped during discovery; selected paths, roots and their existing ancestors reject reparse points. An inaccessible directory can fail discovery. Empty files and files without extensions are accepted. Each source, copied file and new signature is limited to **64 MiB**; content is read into memory. There is no document-format parser or document-content validation.

Calling `Get-ActPlan` without `-AllFiles` or `-SourceFiles` preserves the previous act-filename filter and PDF-header requirement for compatibility with scripts. The application always uses the general mode.

## Output and companion files

Saving beside sources adds a detached SIG in the source directory. Separate output preserves relative paths and copies the selected source byte for byte when a new signature is needed. Only neighboring sidecars whose complete signer set is mathematically verified against that source are copied. Unselected attachments are excluded.

A confirmed selected-certificate signature is skipped without creating a new output bundle or repairing missing copies. Existing copies with matching SHA-256 may be reused; different bytes cause a per-file error. Nothing is overwritten. A late failure may leave a partial set of copies; the entire bundle is not transactional.

The default `file_signer` name includes the full source filename, for example `report.docx_ivanov.sig`. Other retained modes are `signer` (`signature_ivanov.sig`), `document_signer` (`report_ivanov.sig`) and `legacy` (`report.my.sig`). Only the default separates equal stems with different extensions. Concurrent signing of the same bundle is unsupported.

The surname comes from the selected certificate's `surname` attribute. Russian letters are transliterated and unsuitable characters normalized. If no surname is available, the label is `cert_` followed by 12 thumbprint characters. Filenames are labels; signer identity is determined from the signature and certificate.

## Signature verification

Before creating a signature, CSPSigner reads neighboring `.sig`, `.p7s`, `.p7m` and `.sgn` files beside the source file and, for separate output, beside the destination file. Candidate files are reread during processing.

| Result | Behavior |
| --- | --- |
| Selected certificate confirmed over the exact source bytes | `already_signed`, without key access or new copies |
| Other signers identified and their mathematical signatures confirmed | A separate own signature may be added |
| No own signature confirmed and a candidate cannot be verified conclusively | Error for that file; independent files continue |
| User cancels or the shared signing session becomes unusable | Stop the batch; remaining files are `not_processed` |

The comparison uses the exact certificate thumbprint and all actual CMS `SignerInfo` entries. A certificate merely included in the chain is not a signer. A confirmed own signature can end the inspection without requiring all other candidate files to pass.

Supported neighbor formats are detached CMS/PKCS#7, including CAdES, in binary DER/BER, Base64 or PEM `CMS`/`PKCS7`. Local Windows CryptoAPI identifies signers, matches their embedded certificates and verifies the exact detached source bytes without accessing a private key. Embedded PDF/PAdES signatures are not audited by this neighbor check.

Mathematical verification does not establish chain trust, revocation status, certificate validity at a historical time or signer authority. An expired foreign certificate alone does not prevent adding an independent signature. Missing or ambiguous signer certificates, attached content, unsupported structures, trailing bytes and damaged input remain inconclusive.

CMS inspection is limited to 64 MiB per source/signature, 4096 signers and 512 MiB of cumulative source hashing per inspected CMS. General-mode sibling association has separate batch limits of 4096 inspector calls and 512 MiB of snapshot content. Results are cached by source and signature SHA-256. Exhaustion fails conservatively.

A sidecar is excluded from a file's checks only after all signers are mathematically confirmed against another source in the same directory. Filename hints change candidate ordering but never establish identity. Discoverable unselected siblings may be read for this purpose; their signatures are neither created nor copied. The source used as proof and all relevant sidecars are rechecked before signing and publication. Unknown, unreadable or ambiguous ordinary sidecars remain blocking unless an own signature over the current file is confirmed. Explicitly selected signature-extension inputs are also source documents: an inconclusive candidate is exempt from blocking another selection only with proof of that declared source role; an output copy must additionally match the current source bytes. Valid matching CMS evidence from those files still participates in foreign-signature and duplicate checks. Role proofs are rechecked before key use and publication; budget, cancellation and malformed-provider failures are never exemptions.

New signatures use detached **CAdES-BES**, include the public signer certificate and are saved as binary CMS. CryptoPro checks the selected certificate and verifies the new signature before saving. Source and neighbor hashes are rechecked around signing and publication. Empty files use the documented `VerifyHash` path because CAdESCOM does not expose signer information reliably through `VerifyCades` with zero-length content. Native exact-byte verification first authenticates the selected embedded signer and its GOST public-key OID; full CAdES verification then uses the corresponding empty-content hash. No installed My-store certificate or private-key lookup is needed for that verification. Nonempty files retain `VerifyCades`. SHA-256 used by the file logic is separate from the GOST signature algorithm.

No PDF stamp, trusted TSA timestamp, CAdES-T or archival signature format is created. Local `SigningTime` and CSV times are not independent proof of signing time.

## Certificates and backend

Discovery considers the CryptoPro container store (`100`) and the current user's personal store (`CurrentUser\My`, `2`). Certificates must have a private-key association, be currently valid according to Windows time, and use GOST-2012-256 or GOST-2012-512 public-key OIDs (`1.2.643.7.1.1.1.1`, `1.2.643.7.1.1.1.2`). Duplicate thumbprints are merged.

Certificate selection is not saved between launches. A certificate appearing in the list does not prove that its key is accessible at signing time. A public `.cer` alone is insufficient. PIN prompts and caching depend on CryptoPro and the token; one prompt per batch is not guaranteed.

PowerShell handles the UI and file operations. `ActSigner.CryptoPro.js` calls CAdESCOM in local CScript processes. The `ACTSIGNER/1` protocol preserves its existing commands and adds `VERIFYEMPTY` for zero-byte full verification. It uses redirected standard streams, UTF-16LE without BOM and chunked Base64. The JScript helper receives document bytes rather than document paths; private keys and PINs are not sent through this protocol. Base64 is encoding, not encryption.

The signing process starts only for the first new signature and persists for the batch. New-signature verification uses a separate CScript process. On x64 Windows, the backend selects the native 64-bit CScript; it does not automatically retry x86 after an error.

| Operation | Timeout |
| --- | --- |
| Component check, certificate discovery or selection | 60 seconds per request |
| Signing, including waiting for PIN | 10 minutes |
| New-signature verification | 10 minutes |
| Graceful helper shutdown | 5 seconds, followed by bounded termination |

## Settings and logs

`%LOCALAPPDATA%\CSPSigner\settings.json` stores source/output paths, save-beside preference and signature naming. New installations use `file_signer`. On first launch, only supported preferences from `%LOCALAPPDATA%\ActSigner\settings.json` migrate; the previous naming mode is preserved. Existing CSPSigner settings, even malformed files, are never overwritten by migration. Closing the picker also saves preferences. Malformed settings fall back to defaults. No PIN, selected files or certificate selection is persisted.

CSV logs are written to `<output root>\_CSPSigner_logs\act-sign-yyyyMMdd-HHmmss-fff-xxxxxxxx.csv`. Saving beside sources uses the selected source root. Logs use comma separators, quoted fields, UTF-8 with BOM and CRLF. Rows are flushed during processing; formula-like cell prefixes are escaped.

| Field | Meaning |
| --- | --- |
| `Source` | Full source file path |
| `Destination` | Planned new signature path, even when signing was skipped |
| `Hash` | SHA-256 of the source if it was read |
| `Thumb` | Certificate selected for this run, not necessarily the author of an existing SIG |
| `Status` | Processing result |
| `Message` | Explanation, existing signature path or error stage |
| `Time` | Windows time in ISO 8601 with local offset |

| Status | Meaning |
| --- | --- |
| `signed_verified` | New signature verified in memory and saved |
| `already_signed` | Exact source already signed by the selected certificate; no new files |
| `exists_unverified` | Target filename occupied; no own signature confirmed or written |
| `error` | Document failed; independent documents may continue |
| `cancelled` | Cryptographic operation cancelled; batch stopped |
| `not_processed` | Document not reached after the batch stopped |

An occupied target is initially unchecked but can be selected for verification. Its mere existence does not prove validity. Only selected files appear in the CSV. Errors before batch creation may produce no log; forced console closure may leave an incomplete log.

## Updates and recovery

The launcher validates cached versions before use, starts the application locally and checks the latest stable GitHub release in a separate background process. A prepared update is selected on the next launch. Running signing batches stay on their original version.

The updater checks the archive, manifest, sizes, hashes, runtime files, version and PowerShell syntax. Versions are stored under `%LOCALAPPDATA%\ActSigner\updates`; incomplete downloads do not replace the installed application. A verified previous version or the extracted bundle can serve as fallback. Cached version folders are not automatically removed.

From PowerShell in the extracted application directory:

```powershell
# Use the selected local version without a new update check.
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Start-ActSigner.ps1 -NoUpdate

# Use the previous verified version for this launch only.
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Start-ActSigner.ps1 -Previous
```

`-Previous` falls back to the extracted bundle if no previous version is available. The next ordinary launch selects the active version again. Running `Sign-Acts.ps1` directly bypasses the launcher and requires Windows PowerShell 5.1 in STA mode.

Update integrity relies on HTTPS access to the configured GitHub repository and SHA-256; there is no independent publisher signature. The updater does not receive document paths, certificates or PINs and does not access private keys.

## Diagnostics and privacy

Use `diagnostics\Check-CryptoPro.cmd` in the same Windows environment and account as the failure. See [diagnostics/README.txt](diagnostics/README.txt). It writes `diagnostics\ActSigner-diagnostics.txt`, replacing the previous report, and compares direct PowerShell and CScript store access for available architectures. Each probe has a 30-second timeout; a full run with all probes timing out can take about 13 minutes on x64 Windows.

Diagnostic probes read store counts and component information without signing or exporting keys. They omit certificate identities and reduce some path information, but reports still need review before publication. Full signing logs contain paths, thumbprints, hashes and error details. Use synthetic examples in public issues and tests; do not attach production documents, signatures, key containers or PINs.

In a VM, install CryptoPro components and the token driver in the guest, attach the device to that guest and check its availability there. Shared document folders do not provide key access. Incorrect guest time can exclude otherwise suitable certificates.

Document signing is local. Certificate checks by Windows or CryptoPro may require network access, and an independently configured cloud-sync client may upload files. CSPSigner does not install CryptoPro, configure tokens or change VM settings.

## Development and releases

The implementation targets Windows PowerShell 5.1 and built-in Windows Script Host JScript. Source `.ps1` and `.psm1` files use UTF-8 with BOM and CRLF; `.cmd` and `ActSigner.CryptoPro.js` use ASCII and CRLF; Markdown uses UTF-8 and LF.

Run the relevant existing checks from the project directory, using local temporary folders for artifacts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ActSigner.Core.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\CSPSigner.Files.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ActSigner.CryptoPro.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ActSigner.Cms.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ActSigner.Settings.Tests.ps1
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\ActSigner.UI.Tests.ps1 -ArtifactDirectory "$env:TEMP\ActSigner-ui"
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\ActSigner.Console.Tests.ps1 -ArtifactDirectory "$env:TEMP\ActSigner-console"
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Sign-Acts.Tests.ps1 -ArtifactDirectory "$env:TEMP\ActSigner-entry"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ActSigner.Update.Tests.ps1
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Start-ActSigner.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Release.Tests.ps1
```

The automated tests use synthetic fixtures and do not require a production key. Node.js is needed only for the mocked JScript portion of the CryptoPro test; without it that portion reports `SKIP`. Junction/symlink cases may also report `SKIP` when the environment cannot create links. UI and console tests exercise Windows components; these checks do not replace a real CryptoPro/token test on the target system.

`ActSigner.Version.json` is the canonical version source. To prepare a new application release, change `Version` using `MAJOR.MINOR.PATCH` while preserving `LauncherProtocol: 1`. The [release workflow](https://github.com/Alox1d/act-signer/blob/main/.github/workflows/update-release.yml) runs checks on Windows and publishes from `main`.

`tools/Build-Release.ps1` builds public `CSPSigner-VERSION.zip`, an identical compatibility `ActSigner-VERSION.zip`, and `ActSigner-update.json` from an explicit allowlist, including the Russian and English READMEs and this reference. Arbitrary repository files and private data must stay excluded. Build output belongs outside the synchronized checkout.

`tools/Publish-Release.ps1` creates a draft, uploads all three assets, downloads and verifies them, then publishes a stable release. Published versions are immutable; an incomplete draft may be resumed only for the same commit. Release publication is separate from editing documentation.
