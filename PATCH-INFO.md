# PATCH-INFO — feat/ads-stream-filter

- **Issue:** #485 — Filter out files ignored by Dropbox (NTFS Alternate Data Stream)
- **Branch:** feat/ads-stream-filter
- **Worktree:** wt-p15
- **Datum:** 2026-06-16
- **Ziel:** Ordner/Dateien mit einem konfigurierbaren NTFS-Datenstrom-Namen beim Scan überspringen.
  Primärer Anwendungsfall: `com.dropbox.ignored` (Dropbox ignorierte Ordner).
  Implementierung in beiden Scannern (NTFS-Fast + Standard-Finder) + Checkbox in Options.
