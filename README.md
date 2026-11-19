# SecurityCam

<img src="src/Resources/logo.png" width="96" align="right" alt="SecurityCam logo" />

A simple tool for WistaOS that checks `.bat`/`.cmd` and `.exe` files to see whether they show signs of viruses, trojans or other malicious software.

The interface follows the Rufus layout: **Scan Properties**, **Report Options** and a **Status** bar with `START` / `CLOSE`.

## How it scans

Files are analysed **statically and are never executed**. The engine is heuristic, so it is not a replacement for a full antivirus.

- **Batch / CMD**: encoded or hidden PowerShell, download-and-execute chains, `certutil`/`bitsadmin`/`mshta`/`regsvr32` abuse, shadow-copy deletion, Defender tampering, persistence, mass deletion, obfuscation (`%var:~n,m%`, caret escaping, Base64 blobs, embedded PE).
- **Executables (PE)**: extension/content mismatch, packer sections, writable+executable sections, per-section entropy, suspicious API combinations (injection, hooks, anti-debug), forged timestamps, large overlay, Authenticode presence.
- **Hash blocklist** (optional): a text file with one SHA-256 per line; a match is an immediate `Malicious`.

Each finding adds to a 0–100 score: `Clean` < 15, `Low risk` 15–39, `Suspicious` 40–69, `Malicious` ≥ 70. The *Sensitivity* option scales the score.

## Usage

1. Press **SELECT** (or drag files/folders onto the window).
2. Choose scan type and sensitivity.
3. Press **START**. The log icon reopens the last results; reports can be saved as `.txt` or `.csv`.

## Build

Requires the .NET 8 SDK on Windows.

```powershell
cd src
dotnet build -c Release
# single portable exe:
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
```

## License

GPL-3.0, see [LICENSE](LICENSE).
