# idftool

A CLI tool built on top of [`esptool`](https://github.com/espressif/esptool)
that is ESP-IDF partition aware.

## Why idftool?

`esptool` is a generic tool for flashing Espressif modules that works with
arbitrary flash addresses. It does not take into the ESP-IDF partition
table or OTA mechanism, making it unduly difficult to perform simple tasks
such as flashing a new firmware binary or pulling log data from a device -
especially when dealing with multiple devices/partition tables.

`idftool` offers:

- **Partition-name addressing.** Read, write, erase, or hex-dump a
  partition by name (`nvs`, `ota_0`, `storage`, …) — and grab slices of it
  with a `name[start:stop]` syntax.
- **OTA slot management.** Inspect the active slot, switch slots, or roll
  back to factory without hand-computing otadata offsets. `idftool list`
  marks the running OTA partition right in the table.
- **Improved safety features.** Writes are checked to ensure they do not
  overflow the target partition. Firmware binaries are checked to ensure
  compatibility with the chip being flashed.
- **Reproducible multi-binary flashing.** `create-bundle` packs multiple
  partition binaries into a single ZIP; optionally flashing a partition
  table. `write-bundle` reflashes the lot in one command.

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

### Firmware

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

### Images

An image is a single contiguous flash image — everything from the
primary bootloader through the partition table and partitions in one
file. Useful for archiving a known-good snapshot, recovering a bricked
device, or feeding production programmers that can't speak the esptool
protocol.

#### `create-image`
Combine partition images into a single contiguous flash image, offline,
from local files and a partition table.
```text
idftool --partition-table-file partitions.csv create-image \
  -o merged.img --flash-partition-table \
  ota_0 build/app.bin storage build/spiffs.bin
```

#### `dump-image`
Read the entire flash to an image file. If no output filename is given,
the file is named `{chip}-{mac}-{timestamp}.img` (e.g.
`esp32-s3-aabbccddeeff-20260522-143000.img`). Works even when the
on-device partition table is corrupted.
```text
idftool dump-image                 # auto-named
idftool dump-image my-backup.img
```

#### `write-image` (alias: `reflash`)
Erase the entire flash and rewrite it from a flash image. The
counterpart of `dump-image`.
```text
idftool write-image build/full-flash.img
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

#### `dump-bundle`
Read every partition from the device and pack them into a bundle ZIP,
always including `partition_table.csv`. If no output filename is given,
the file is named `{chip}-{mac}-{timestamp}.zip`.
```text
idftool dump-bundle                  # auto-named
idftool dump-bundle my-backup.zip
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
