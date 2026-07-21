# Changelog

## v0.1.4

- Add `chip_name` property to `ChipId`.

## v0.1.3

- Replace `ESPLoader` dependency in `print_partition_table` with a generic `read` callable; tolerate read errors so unreadable app slots render empty.

## v0.1.2

- Add `OtaImageState` enum and typed `ota_state` field.

## v0.1.1

- Require Python 3.10+.
- Add license metadata and source URL.
- Add README for PyPI project page.
- Update GitHub Actions to latest versions.

## v0.1.0

- Initial standalone release of `esp-idf-defs` after extraction from the combined `idftool` repo.
