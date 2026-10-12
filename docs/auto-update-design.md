# ActSigner startup updates

## Intent

The user wants ActSigner to update from its public GitHub repository at startup without manually replacing ZIP archives. Startup must remain usable when networking fails, and an update must never interrupt a running signing batch. Existing folder preferences, documents, signatures and keys are outside the updater's write scope.

## Chosen behavior

`Start.cmd` retains native Windows PowerShell 5.1, STA, exit-code propagation and the final pause. It invokes `Start-ActSigner.ps1`, a bundled launcher that validates and chooses a complete local application version before starting the application in a separate native PowerShell process. It starts `Update-ActSigner.ps1` as a hidden, noninteractive background process. No network request runs in the foreground launcher. A prepared update applies on the next launch, never halfway through this invocation. `-NoUpdate` suppresses networking; `-Previous` selects the previous valid cached version or the bundled fallback and also suppresses networking for that invocation.

The trusted bundled `ActSigner.Update.psm1` performs initial cache validation. A cached updater is executed only after that cache has passed validation. Each future worker loads its sibling updater module, allowing updater logic to evolve with releases while launcher protocol 1 remains stable.

## Distribution contract

- Repository: `Alox1d/act-signer`; public HTTPS requests require neither Git nor credentials.
- Stable release tag: `vMAJOR.MINOR.PATCH`; all numeric components are nonnegative decimal integers without leading zeros and fit Int32. Draft and prerelease releases are rejected.
- Root `ActSigner.Version.json`: `SchemaVersion: 1`, `Version: "1.5.0"`, `LauncherProtocol: 1`.
- Release assets: `ActSigner-MAJOR.MINOR.PATCH.zip` and `ActSigner-update.json`.
- JSON manifest fields: `SchemaVersion`, `Version`, `LauncherProtocol`, `Repository`, `SourceCommit` (40 hexadecimal characters), `AssetName`, `Size`, `Sha256`, and `Files`.
- Each `Files` item has `Path` (relative ASCII path using `/`), `Size`, and lowercase hexadecimal `Sha256`. The ZIP contains exactly those file entries, with no wrapper directory or additional manifest. The downloaded manifest is stored as `payload-manifest.json` after validation.
- Release building uses an explicit source allowlist. Tests, workflows, user settings, documents, signatures, private data and diagnostic results are never release payloads.
- The release workflow runs native Windows verification before creating a draft, uploading both assets, and publishing the stable release. Published versions/assets are never overwritten; a new change requires a version bump.

## Storage and transaction

Updater state is `%LOCALAPPDATA%\ActSigner\updates`, independently of `settings.json`. Version directories are `versions/vVERSION-SHA256PREFIX`, where the prefix is the first 16 hexadecimal ZIP digest characters. Each contains a complete immutable payload and its manifest. No automatic version cleanup is introduced in this release.

`active.json` has `SchemaVersion: 1`, `Active` and nullable `Previous`. Each selection records `Directory`, `Version`, and `ManifestSha256`. Both pointers change in one atomic same-directory file replacement. The installer holds an exclusive file stream lock throughout the transaction; lock-file existence alone is not a lock. An unavailable lock causes the second worker to exit promptly.

Download to a unique staging directory, validate metadata and archive digest, inspect every ZIP entry before extraction, validate actual file sizes and hashes, validate version JSON and parse shipped PowerShell scripts, publish the complete version directory, then replace active state. Any failure retains the previous pointer. A completed version directory with an uncommitted pointer is harmless. Corrupt state or cache falls back to a verified previous cache when appropriate, otherwise the bundled version. Normal selection never downgrades a newer bundled version. `-Previous` intentionally permits a lower previous version for one invocation and never mutates active state.

## Bounds and trust

The updater accepts only fixed HTTPS GitHub repository endpoints, with bounded requests, redirects and payload sizes. Use HttpClient without implicit credentials, no certificate-validation bypass and no expression evaluation. Initial metadata URL is `https://api.github.com/repos/Alox1d/act-signer/releases/latest`; assets must use matching `https://github.com/Alox1d/act-signer/releases/download/vVERSION/NAME` URLs. HTTPS redirects may go only to GitHub release asset hosts. Maximum manifest 256 KiB, ZIP 8 MiB, file 2 MiB, uncompressed payload 16 MiB, 100 file entries. Reject traversal, rooted paths, backslashes, colons/ADS, reserved Windows names, case-insensitive duplicate destinations, links/reparse points and unexpected entries before writing extracted files. Cache ancestors under the chosen state root must not redirect writes through reparse points.

SHA256 checks establish consistency with the HTTPS GitHub release, not a separately signed publisher identity or protection against a malicious actor who can replace the same user's local code and state. No signing key or token is used by the updater. Unknown protocol/schema, downgrade, network outage, missing release, rate limit and cache access failure leave the installed program runnable.

## Component interfaces

`ActSigner.Update.psm1` exports:

- `Get-ActUpdateStateRoot`: returns the default state directory.
- `Get-ActLaunchSelection -BundledRoot <string> -StateRoot <string> [-Previous]`: returns `ApplicationRoot`, `Version`, `UsingCached`, `Rollback`, `Notice`. This is local-only and performs no network request.
- `Invoke-ActUpdateCheck -ApplicationRoot <string> -StateRoot <string> [-ReleaseProvider <scriptblock>] [-Downloader <scriptblock>]`: returns `Status`, `Version`, `Message`. Optional providers are deterministic test seams matching existing project patterns. `ReleaseProvider` returns the GitHub release object; `Downloader` receives `(Url, Destination, MaxBytes)` and writes that destination. Production calls use the bounded HTTP implementation. Status is `updated`, `current`, `busy`, `unavailable` or `unsupported`.

The worker imports only its sibling module and invokes the updater with its own application root. The launcher selects one application snapshot before starting the worker; it never rereads the active pointer to switch an already chosen invocation. The updater may write a small bounded `status.json` containing non-sensitive status/version/message for user-facing notification. It never receives PDF paths, certificate identities or signing callbacks.

## Verification

Meaningful tests must exercise real ZIP/filesystem behavior and native subprocess launches. Cover successful staging and next-launch selection; digest/version/path/size rejection; interrupted installation and pointer failure; corrupt cache/state and rollback; exclusive lock and crash recovery; offline behavior without foreground waiting; paths with Cyrillic, spaces and shell metacharacters; STA/exit propagation; preservation of user settings and synthetic document/signature bytes. Tests use synthetic data and never initiate a real signing operation.
