# Neighbor signature correction

An existing signature from another certificate must not prevent adding a separate
signature just because its certificate chain has expired. Preserve all original
document and signature bytes. Keep full validation of the selected signing
certificate and newly created signature.

Read every real CMS SignerInfo and resolve only its corresponding certificate.
Certificate bags are not signer lists. Reject missing or ambiguous identities.
Separate identity, mathematical verification over exact PDF bytes, and trust,
validity and revocation. A confirmed selected-certificate signature skips key
access. An unresolved possible selected-certificate signature blocks that act.

Continue independent acts after document errors. Stop separately for user
cancellation and shared signing-session failures. Preserve settings, default
adjacent output, no-overwrite rules and GitHub Release updates.

Public tests use synthetic data. Private documents, signatures, certificates,
keys, PINs and unredacted logs stay outside Git. Prove native Windows PowerShell
5.1 and installed CryptoPro/GOST behavior on copies before publishing the next
unused patch version through the existing main-push workflow.

User addition: default new filenames use signature_<certificate surname transliterated>.sig.
Expose and remember signer, document+signer and legacy .my.sig formats. Do not infer
surname from organization/common-name fields. Missing surname uses a certificate
identifier. Validate labels, reject same-target documents before key access, preserve
old signature discovery and never overwrite or rename user files.
