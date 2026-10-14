# CSPSigner

[Русский](README.md)

CSPSigner is a Windows utility for batch signing files through **CryptoPro CSP**. Select documents and a certificate to create a separate **CAdES-BES** signature for each file. Source bytes remain unchanged. The application interface is in Russian.

**[Download the latest release](https://github.com/Alox1d/act-signer/releases/latest)** - extract the entire `CSPSigner-VERSION.zip` archive and open `Start.cmd`.

## Example uses

- Sign documents, spreadsheets, XML or archives in one batch.
- Add your signature to a file already signed by another party.
- Prepare source files and signatures for sharing or archiving.

## Requirements

- A Windows desktop and built-in **Windows PowerShell 5.1**. `Start.cmd` selects the required host.
- Installed **CryptoPro CSP**, local **CAdESCOM** components and Windows Script Host (`cscript.exe`). [CryptoPro component downloads](https://www.cryptopro.ru/products/cades/downloads).
- A currently valid **GOST R 34.10-2012** certificate with access to its private key. USB tokens also require their driver.
- Read access to source files and write access to the output folder. Each file is limited to **64 MiB**.

In a VM, components and the key must be available inside the Windows guest. Running the application requires no Python, Node.js or build step.

## Sign files

1. Open **`Start.cmd`**.
2. Choose output placement, certificate and signature naming format. **Подробнее** (details) shows certificate information and diagnostics.
3. Select a source folder and click **Найти файлы** (find files) to scan it and its subfolders. Use **Выбрать файлы...** (select files) for individual documents.
4. Review the list, select files and click **Проверить и подписать** (check and sign).
5. Enter the PIN in the standard CryptoPro or token dialog and wait for the console summary.

If you change folders, certificate or naming format after discovery, rebuild the list.

Content formats are unrestricted: PDF, DOCX, XLSX, XML, ZIP, images and other files can be signed. Folder search excludes signature files, `.tmp`, application logs and a nested output folder. Use the file picker to select such files explicitly.

## Output

By default, the full source filename is included in the signature name:

```text
Documents/
  report.docx
  report.docx_ivanov.sig
  report.pdf
  report.pdf_ivanov.sig
```

The surname comes from the certificate and is transliterated into Latin characters. A missing surname falls back to `cert_<12 thumbprint characters>`. Multiple documents can share a folder.

| Naming format | Example |
| --- | --- |
| Full filename and surname, default | `report.docx_ivanov.sig` |
| Surname only | `signature_ivanov.sig` |
| Filename without extension and surname | `report_ivanov.sig` |
| Legacy format | `report.my.sig` |

Use the default format for several files in one folder: other formats may produce identical target names. Existing files are never overwritten.

Separate output preserves subfolders and copies the selected source and signatures mathematically confirmed over it. Other attachments are not copied automatically. Keep **the original file and matching SIG** together for verification. No visible stamp or embedded document signature is added.

## Repeat runs and verification

CSPSigner checks neighboring `.sig`, `.p7s`, `.p7m` and `.sgn` files regardless of their names and matches them to exact file bytes.

- A confirmed signature by the selected certificate produces `already_signed`: no new signature or copies are created, and the key is not accessed.
- A confirmed foreign signature allows adding your own. An expired foreign certificate does not block this by itself.
- A signature belonging to another file is excluded from the current file's check only after successful mathematical verification against that other source.
- Damaged or inconclusive signatures block the current file; independent files continue.
- Cancellation of a cryptographic operation or an unusable shared session stops the batch. Saved results remain.

CryptoPro verifies every new signature before saving it. Mathematical verification of existing signatures does not establish certificate trust or historical signing time. No trusted timestamp or complete long-term validation bundle is created.

## Settings and updates

Settings are stored in `%LOCALAPPDATA%\CSPSigner\settings.json`. ActSigner preferences migrate automatically on first launch, including the previous naming format. CSV logs are stored in `<output folder>\_CSPSigner_logs`.

`Start.cmd` checks stable GitHub releases in the background. A verified update takes effect on the next launch. Previous internal module names, repository URL and `%LOCALAPPDATA%\ActSigner\updates` cache are retained for compatibility with installed versions.

## Troubleshooting

- Missing certificate or CryptoPro error: click **Подробнее**, then run `diagnostics\Check-CryptoPro.cmd`. [Diagnostic instructions, in Russian](diagnostics/README.txt).
- Console waiting: use Alt+Tab to check the PIN dialog. If its title contains **Выбрать / Select**, press Esc.
- To [report an issue](https://github.com/Alox1d/act-signer/issues), include the version, failing stage and error message. Do not attach keys, PINs or production documents.

[Technical reference and development](REFERENCE.md) - limits, logs, recovery, tests and release packaging.
