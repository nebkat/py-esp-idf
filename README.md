# idftool

A CLI built on top of [`esptool`](https://github.com/espressif/esptool)
with ESP-IDF partition-aware helpers - a long missing tool in the ESP-IDF
ecosystem.

## Why idftool?

`esptool` is designed for flashing Espressif modules but it does not take
into account ESP-IDF features such as partition tables and OTA schemes.
This makes it unduly difficult to perform simple tasks such as flashing a
new firmware binary or pulling log data from a device, requiring memorizing
raw flash addresses.

`idftool` offers:

- **Partition-name addressing.** Read, write, erase, or hex-dump a
  partition by name (`nvs`, `ota_0`, `storage`, …) — and grab slices of it
  with a `name[start:stop]` syntax.
- **OTA slot management.** Inspect the active slot, switch slots, or roll
  back to factory without hand-computing otadata offsets. `idftool list`
  marks the running OTA partition right in the table.
- **Reproducible multi-binary flashing.** `create-bundle` packs a
  partition table plus every partition image into a single ZIP;
  `write-bundle` reflashes the lot in one command.
- **`enter-bootloader`.** A fast-polling helper that drops the device into
  ROM download mode the instant the USB port shows up — handy for flaky
  USB-serial bridges or boards where the timing of the BOOT/RESET dance
  matters.

> Pre-built binaries are published on the
> [Releases](https://github.com/nebkat/py-esp-idf/releases) page.
> See `CONTRIBUTING.md` for building from source.

## At a glance

```bash
$ idftool devices
/dev/cu.usbmodem1101 || USB JTAG/serial debug unit || USB VID:PID=303A:1001 SER=...

$ idftool list
| Name     | Type | Subtype  | Offset   | Size | App description |
|----------|------|----------|----------|------|-----------------|
| nvs      | data | nvs      | 0x9000   | 16K  |                 |
| otadata  | data | ota (A)  | 0xd000   | 8K   |                 |
| phy_init | data | phy      | 0xf000   | 4K   |                 |
| ota_0    | app  | ota_0    | 0x10000  | 1M   | my-app v1.0.0   |
| ota_1    | app  | ota_1    | 0x110000 | 1M   | my-app v1.1.0 * |
| storage  | data | spiffs   | 0x210000 | 1M   |                 |

# The trailing `*` marks the currently-active OTA app

$ idftool ota build/my-app.bin
Writing 'my-app v1.2.0' to partition 'ota_0'...
Setting boot partition to 'ota_0'...

$ idftool write nvs my-nvs.bin
Writing file my-nvs.bin (size=0x4000) to partition nvs (offset=0x9000, size=0x4000)

$ idftool set-boot ota_1
Setting boot partition to 'ota_1'...
```

## Global options

These flags apply to every subcommand and go **before** the command name:

| Flag | Purpose |
|------|---------|
| `-p`, `--port PATH` | Serial port device. If omitted, idftool auto-picks one. |
| `-b`, `--baud N` | Serial baud rate (defaults to esptool's ROM baud, 115200). |
| `--no-reset` | Skip the hard reset that normally happens after a command. |
| `--partition-table-file PATH` | Use a CSV or binary partition table from disk instead of reading it off the device. |
| `--partition-table-offset OFFSET` | Where to expect the partition table in flash (default `0x8000`). |
| `--partition-table-size SIZE` | Size of the partition table region (default `0x1000`). |
| `--primary-bootloader-offset OFFSET` | Primary bootloader offset, or a chip name like `esp32s3` to pick a default. Only needed when addressing the `bootloader` partition by name in **offline** mode (`--partition-table-file` with no device); auto-detected from a connected chip otherwise. |
| `--recovery-bootloader-offset OFFSET` | Recovery bootloader offset; same scope as `--primary-bootloader-offset`. |

The commands `list`, `merge-bin`, and `create-bundle` will work **without**
a device when you supply `--partition-table-file`; everything else needs a
connected ESP.

## Partition addressing

Wherever a command takes a `partition` argument you can pass:

- A **name** from the partition table (`nvs`, `ota_0`, `storage`, …).
- A **numeric address** that matches an existing partition's start
  offset exactly — equivalent to looking the partition up by name, just
  keyed on its address.
- An **offset into a partition**: `name[offset]`. Negative values count
  from the end. Sets the starting point for the operation. Accepted by
  `write` and `merge-bin`.
- A **slice of a partition**: `name[start:stop]`. Negative values count
  from the end, and a `+N` stop is a length relative to `start`.
  Accepted by `read`, `erase`, and `view`. Examples:
  - `nvs[0:0x100]` — first 256 bytes of `nvs`
  - `storage[-0x1000:]` — last 4 KiB of `storage`
  - `ota_0[0x1000:+0x800]` — 2 KiB starting 4 KiB into `ota_0`

All numeric values in addresses, offsets, and sizes accept either
decimal (`4096`) or hex (`0x1000`).

---

## Command reference

### Discovery

#### `devices`
List the serial ports the host can see, with their descriptions and USB
hardware IDs.
```text
idftool devices
```

#### `list`
Print the device's partition table. With a connected ESP, idftool also
reads the application descriptor of every app partition (project name,
version) and marks the currently-active OTA slot with a trailing `*`. The
selected otadata copy is shown next to the otadata partition's subtype
(`ota (A)`, `ota (B)`, or `ota (invalid)` when otadata is erased).
```text
idftool list
idftool --partition-table-file partitions.csv list   # offline
```

### Partition I/O

#### `read`
Read a partition (or slice) into a file.
```text
idftool read nvs nvs.bin
idftool read 'storage[-0x1000:]' tail.bin
```

#### `write`
Write one or more files to named partitions. Arguments come in
`PARTITION FILENAME` pairs; you can repeat them to flash several
partitions atomically.
```text
idftool write ota_0 build/app.bin storage build/spiffs.bin
```

#### `erase`
Erase a partition (or slice of one).
```text
idftool erase nvs
```

#### `view`
Pretty-print a partition's contents. Hex dump by default; pass `-s` for
UTF-8 string mode and `-w` to tweak the dump width.
```text
idftool view nvs
idftool view nvs -w 32
idftool view nvs -s
```

### Firmware binaries/images

#### `ota`
Push a new app image to the **next** OTA slot, then set it as the boot
slot. idftool figures out which slot is next from otadata, writes the
image, and bumps the OTA sequence counter — exactly what an OTA update
from the firmware would do, just over USB.
```text
idftool ota build/my-app.bin
```

#### `factory`
Write an app to the factory partition and erase otadata so the bootloader
falls back to factory on next boot. If the device has no factory
partition, the image is written to `ota_0` instead.
```text
idftool factory build/my-app.bin
```

#### `reflash`
Erase the entire flash and rewrite it from a full flash image (everything
from the primary bootloader onward). Useful for restoring a known-good
image or recovering a bricked device.
```text
idftool reflash build/full-flash.bin
```

### Boot selection

#### `get-boot`
Print which OTA slot the bootloader will run on the next reset, along
with the sequence number and OTA state.
```text
idftool get-boot
```

#### `set-boot`
Force the next boot to a specific OTA partition by name (e.g. `ota_0`,
`ota_1`).
```text
idftool set-boot ota_1
```

#### `clear-boot`
Erase the otadata partition. The bootloader's fallback then kicks in: if
a factory partition exists it boots factory, otherwise it boots `ota_0`.
The OTA app images themselves are left untouched.
```text
idftool clear-boot
```

### Bundles

A bundle is a plain ZIP file containing one `*.bin` per partition (named
after the partition) and, optionally, a `partition_table.csv`. Bundles
are useful for hand-off between build and flash steps and for archiving a
reproducible "this is what shipped" snapshot.

#### `create-bundle`
Pack partition images into a bundle ZIP. Pass `--flash-partition-table`
to embed the partition table CSV so `write-bundle` can also reflash it.
```text
idftool --partition-table-file partitions.csv create-bundle \
  -o release.zip --flash-partition-table \
  ota_0 build/app.bin storage build/spiffs.bin
```

#### `write-bundle`
Flash every binary in a bundle ZIP. If the bundle contains
`partition_table.csv`, idftool uses it (and rewrites the on-device table
to match) instead of reading the table from flash.
```text
idftool write-bundle release.zip
```

### Misc

#### `enter-bootloader`
Wait for a serial port to appear, then run the BOOT0+RESET dance to drop
the chip into the ROM bootloader (a.k.a. firmware download mode) — and
exit immediately, leaving the device parked for whatever tool you want to
hand it off to. The port path is polled at 50 ms intervals, and transient
errors (e.g. `termios.error: Device not configured` from a tty node that
isn't fully settled) are retried silently.
```text
idftool -p /dev/cu.usbmodem1101 enter-bootloader
```
Requires `-p`/`--port`.

#### `merge-bin`
Combine partition images into a single contiguous flash image — `raw`,
Intel `hex`, or `uf2`. Useful for production programmers and bootstraps
that can't speak the esptool protocol.
```text
idftool --partition-table-file partitions.csv merge-bin \
  -o merged.bin -f raw --flash-partition-table \
  ota_0 build/app.bin storage build/spiffs.bin
```

---

## Troubleshooting

**The device isn't detected, or detection is flaky.**
Run `idftool -p <port> enter-bootloader` first. It uses a tighter polling
loop than the default connect and tolerates the brief window where the
tty node exists but isn't yet fully usable.

**After `clear-boot` the device boots the same partition it was running
before.**
That's normal — `clear-boot` only erases otadata; the bootloader's
fallback target is the factory partition (if present) and otherwise
`ota_0`. If the previously-running slot happens to be the fallback, the
running app looks unchanged. Use `set-boot` to pick an explicit slot.

**`factory` ran but there's no factory partition.**
idftool falls back to writing `ota_0`, then erases otadata so the device
boots that image on next reset.

**Slice ranges look wrong.**
Offsets and lengths must lie within the partition's size; negative
indices count from the end, and a `+N` stop is a length, not an
absolute offset. See *Partition addressing* above for examples.
