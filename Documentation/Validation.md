# TripplePulsar Vault (TPV) 3.0 — Validation Report

Date generated: 2026-03-31

## Validation Summary

The current TPV 3.0 repository was validated against the cleaned publication layout intended for GitHub.

Completed checks:

- `cargo generate-lockfile` completed successfully
- `cargo check` completed successfully
- `cargo build --release` completed successfully
- `cargo run` launched successfully and performed a clean secure exit
- `cargo deny check` completed successfully with warnings only

## Notes

Non-blocking warnings observed during `cargo deny check`:

- unmatched allowed licenses for `ISC` and `Zlib`
- duplicate crate versions for `cpufeatures`
- duplicate crate versions for `windows-sys`

These warnings did not cause the advisories, bans, licenses, or sources checks to fail.

## Repository Scope

This manifest covers the current publish-ready source and documentation set.

Excluded from this manifest:

- `target/` build artifacts
- temporary files and logs
- `Documentation/Validation.md` itself, since it is regenerated from the hashes below
- `Documentation/htru2.zip`

## SHA-256 Manifest

```text
ECC9F4D7C2418E710EF18D4C04914998A1C129699A07061A0649412BFECE4FB2  Cargo.toml
DBC54A2D508242D5377BD0D90BFECFD6960F10F2CE7BA1958F973B6A1EB1C687  Cargo.lock
3E3674A08736F136C8B719B965DCB661808E95ADCDAF2C25D51E97506A99195D  deny.toml
D91236431891C6F576CA64378A634944FED655AAA6F0140E278FB6CD711CD763  .gitignore
1F4BB7CFBEB04676E0F580D1C88F98561832E2873A0F06B0681A02D91B220B47  README.md
96A4320ABFBE955DB4AAF1C5C92E5A84E93782B12377406EE46E63AE1A95A75A  src\crypto.rs
8775C8E3CF75EEB52E74DB45733202906A7122E53BBB3114942F21133B3DDE8C  src\format.rs
FACCA9EADB8C0F5A3C7020A18A13E8864756B2BEE9AA08EFFFC03FC9789D0EA3  src\main.rs
C475A0021014A7CCA0FE836E0DD07E6F5F20C1EC405D7D77EF7BAC7678364BCC  src\shred.rs
5DD89744973D64E496B15265C9E573B4E86527FC23728231E7B484E87BC7F881  src\win32.rs
1F4BB7CFBEB04676E0F580D1C88F98561832E2873A0F06B0681A02D91B220B47  Documentation\README_updated.md
D92CFE4741C8F92CFE5FD4A094AF211CC08511E1E5730AC788411E818398DCE6  Documentation\THREAT_MODEL.md
9F60A312B67E80CC1B3DACEA02EE6FEA38F92566467EBF9714444B9FC698C14A  Documentation\TPF2_FILE_FORMAT.md
3EDF8FD92E3D7B38521123BE37BC98FB1DD47DBE7D19CE6AC679F498C4746C24  Documentation\TripplePulsarVault_Architecture_Security_Overview.md
9D31E952B4C5A71A2D6F624D3F319D6BC21BF20ED63B1DD23EAEE8C99E05CD3B  Documentation\TripplePulsarVault_White_Paper.md
```

## Release Status

TripplePulsar Vault 3.0 passed source validation, release-build validation, runtime launch validation, and dependency policy validation for the current repository state. The project is ready for GitHub publication.
