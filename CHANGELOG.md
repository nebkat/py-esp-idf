# Changelog

## v0.1.6

- `print_partition_table` only reads the app description for app partitions.

## v0.1.5

- `print_partition_table` now tolerates any exception from its `read` callable, not just `OSError`/`ValueError`; a failed read renders as `<READ ERROR>` in the app description column instead of propagating (e.g. esptool's `FatalError` on a comms error, which aborted the caller).

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
