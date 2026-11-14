# Changelog

## v0.1.8

- Ship a `py.typed` marker; the API is annotated and passes `mypy --strict`, so consumers no longer need `follow_untyped_imports` or `untyped_calls_exclude` for it.
- `OtaDataParameters.a_or_b` is typed `Literal['a', 'b'] | None`, as `OtaDataSelectEntry.select()` returns it when neither entry is valid.
- `ImageHeader`'s `spi_mode`, `spi_frequency`, `spi_size` and `chip_id` are typed without `None`, as `from_bytes` always sets them.
- `ImageHeader.max_chip_rev_full` is read from its own offset; it held the last SPI pin drive byte and the low byte of `chip_id`.
- `OtaDataSelectEntry.from_bytes` checks the entry's CRC, returning `None` for an entry with a bad one, as the bootloader ignores it.
- The partition table MD5 mismatch error shows the parsed digest in hex.

## v0.1.7

- Add `ResetReason`, `esp_reset_reason_t` as `esp_reset_reason()` returns it, with `is_watchdog`.

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
