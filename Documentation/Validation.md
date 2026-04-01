# TripplePulsar Vault (TPV) 3.0 — Validation Report

Date generated: 2026-03-31
Finalized after code and documentation update completion.

## Validation Summary

The current TPV 3.0 repository was validated against the finalized source and documentation set.

Completed checks:

- `cargo check` completed successfully
- `cargo build --release` completed successfully
- `cargo run` launched successfully
- TPM provider check completed successfully from the interactive menu
- secure exit completed successfully from the interactive menu
- `cargo deny check` completed successfully with warnings only

## Runtime Verification Notes

Observed interactive runtime path:

1. Application launched successfully through `cargo run`
2. Menu option `5` confirmed that the Microsoft Platform Crypto Provider is available
3. Menu option `8` performed a clean secure exit

## `cargo deny check` Result

`cargo deny check` completed with:

- `advisories ok`
- `bans ok`
- `licenses ok`
- `sources ok`

Non-blocking warnings observed:

- unmatched allowed license entry: `ISC`
- unmatched allowed license entry: `Zlib`
- duplicate crate versions for `cpufeatures`
- duplicate crate versions for `windows-sys`

These warnings did **not** cause the deny check to fail.

## Repository Scope

This manifest covers the current publish-ready source and documentation set.

Excluded from this manifest:

- `target/` build artifacts
- temporary files and logs
- `Documentation\Validation.md` itself, since it is regenerated from the hashes below
- `Documentation\htru2.zip`

## SHA-256 Manifest

```text
D91236431891C6F576CA64378A634944FED655AAA6F0140E278FB6CD711CD763  .gitignore
ECC9F4D7C2418E710EF18D4C04914998A1C129699A07061A0649412BFECE4FB2  Cargo.toml
DBC54A2D508242D5377BD0D90BFECFD6960F10F2CE7BA1958F973B6A1EB1C687  Cargo.lock
3E3674A08736F136C8B719B965DCB661808E95ADCDAF2C25D51E97506A99195D  deny.toml
36A774A68BF920DCE3B931882963F1354F8B708F55B45CD95CD9711B09F96893  README.md
49911740A9A2AA59941F07FC64AF888A6CE4106CC3B8F56CD213E19D3AA431DC  src\crypto.rs
8775C8E3CF75EEB52E74DB45733202906A7122E53BBB3114942F21133B3DDE8C  src\format.rs
18E7083AA59037FD6F9697FF75A95502DCC0D0A7750592043AD6CD75AAC6276A  src\main.rs
C475A0021014A7CCA0FE836E0DD07E6F5F20C1EC405D7D77EF7BAC7678364BCC  src\shred.rs
8C6CCB94208458BF4AE9C5D69D97281BF3D5DEC790EBA179622C921726EFECFD  src\win32.rs
36A774A68BF920DCE3B931882963F1354F8B708F55B45CD95CD9711B09F96893  Documentation\README.md
555C8A6B75EE503527289148C95B3D3964DC28F006452323234088369BBB6563  Documentation\THREAT_MODEL.md
536064FF2B4DECFE5935B2FCD7A74C13C8E733C72212B9DD15CC76B597994AE8  Documentation\TPF2_FILE_FORMAT.md
23405E24B3A84BF0F6DF77AA2F24B48707EB4F87ED162631C5BE79B44AB18AF4  Documentation\TripplePulsarVault_Architecture_Security_Overview.md
68FC9811D6229781D0CAD90397A30EF81CC2BDF0439ED5CD7506A8F5D4B4CCB0  Documentation\TripplePulsarVault_White_Paper.md
```

## Final Status

Final observed state for the repository:

- source compiles successfully
- release build succeeds
- interactive runtime launches successfully
- TPM provider path was verified on the target Windows environment
- secure exit path was verified
- deny-policy checks pass with warnings only
- source and documentation hashes have been regenerated for the finalized file set

This validation report reflects the finalized TPV 3.0 state validated in the current session.
