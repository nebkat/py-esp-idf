from __future__ import annotations
import argparse
import dataclasses
import os
from typing import Literal

import serial.tools.list_ports as list_ports
from build.lib.esptool.loader import ESPLoader
from esptool import erase_flash

from esp_idf_defs.image_metadata import ImageMetadata, ChipId
from esp_idf_defs.otadata import OtaDataSelectEntry
from esp_idf_defs.partitions import PARTITION_TABLE_SIZE, PARTITION_TABLE_OFFSET, PartitionTable, TYPES, SUBTYPES, \
    DATA_TYPE, APP_TYPE, NUM_PARTITION_SUBTYPE_APP_OTA, PartitionDefinition, \
    print_partition_table
from esptool.cmds import detect_chip, write_flash

def auto_int(x):
    return int(x, 0)

@dataclasses.dataclass
class OtaDataParameters:
    partition: PartitionDefinition
    otadata: OtaDataSelectEntry | None
    a_or_b: Literal['a', 'b']
    app_count: int

    def incremented_and_swapped(self, ota_slot: int) -> OtaDataParameters:
        return OtaDataParameters(
            partition=self.partition,
            otadata=self.otadata.incremented(ota_slot, self.app_count)
            if self.otadata else OtaDataSelectEntry.from_ota_slot(ota_slot),
            a_or_b='a' if self.a_or_b == 'b' else 'b',
            app_count=self.app_count
        )

    @property
    def slot(self):
        if not self.otadata:
            return None
        else:
            return self.otadata.ota_slot(self.app_count)

    @property
    def next_slot(self) -> int:
        if not self.otadata:
            return 0
        else:
            return (self.otadata.ota_slot(self.app_count) + 1) % self.app_count

def read_otadata(esp: ESPLoader, partition_table: PartitionTable) -> OtaDataParameters:
    ota_app_count = len(list(
        part for part in partition_table if
        part.type == APP_TYPE and SUBTYPES[APP_TYPE]['ota_0'] <= part.subtype <=
        SUBTYPES[APP_TYPE]['ota_15'] + NUM_PARTITION_SUBTYPE_APP_OTA)
    )
    if ota_app_count == 0:
        raise ValueError("No OTA partitions found") # TODO Better error type

    otadata_partition = next(
        (p for p in partition_table if p.type == DATA_TYPE and p.subtype == SUBTYPES[DATA_TYPE]['ota']),
        None
    )
    if not otadata_partition:
        raise ValueError("No otadata partition found") # TODO Better error type

    otadata_a_bytes = esp.read_flash(otadata_partition.offset, OtaDataSelectEntry.SIZE)
    otadata_b_bytes = esp.read_flash(otadata_partition.offset + esp.FLASH_SECTOR_SIZE, OtaDataSelectEntry.SIZE)
    otadata_a = OtaDataSelectEntry.from_bytes(otadata_a_bytes)
    otadata_b = OtaDataSelectEntry.from_bytes(otadata_b_bytes)

    otadata, a_or_b = OtaDataSelectEntry.select(otadata_a, otadata_b)

    return OtaDataParameters(otadata_partition, otadata, a_or_b, ota_app_count)

def write_otadata(esp: ESPLoader, otadata: OtaDataParameters):
    esp.flash_begin(
        size=OtaDataSelectEntry.SIZE,
        offset=otadata.partition.offset + (0 if otadata.a_or_b == 'a' else esp.FLASH_SECTOR_SIZE)
    )
    esp.flash_block(data=otadata.otadata.to_bytes(), seq=0)
    esp.flash_finish()

def load_app_binary(app_binary_file: str, partition: PartitionDefinition) -> (bytes, ImageMetadata):
    app_binary_size = os.path.getsize(app_binary_file)
    if app_binary_size > partition.size:
        raise RuntimeError(
            f"Application binary size '{app_binary_size}' is greater than partition size {partition.size}")

    app_binary = open(app_binary_file, 'rb').read()
    try:
        image_metadata = ImageMetadata.from_bytes(app_binary, app_required=True)
    except ValueError as e:
        raise RuntimeError(f"Invalid application binary: {e}")

    return app_binary, image_metadata

def command_set_boot(esp: ESPLoader, partition_table: PartitionTable, label: str):
    otadata = read_otadata(esp, partition_table)

    partition = partition_table[label]
    if partition.type != TYPES['app']:
        raise ValueError(f"Partition {label} is not an app partition")
    if partition.subtype < SUBTYPES[APP_TYPE]['ota_0'] or partition.subtype > SUBTYPES[APP_TYPE]['ota_15']:
        raise ValueError(f"Partition {label} is not an OTA partition")
    ota_slot = partition.subtype & 0x0F

    print(f"Setting boot partition to '{partition.name}'...")
    otadata = otadata.incremented_and_swapped(ota_slot)
    write_otadata(esp, otadata)

def command_clear_boot(esp: ESPLoader, partition_table: PartitionTable):
    otadata_partition = next(
        (p for p in partition_table if p.type == DATA_TYPE and p.subtype == SUBTYPES[DATA_TYPE]['ota']),
        None
    )
    if not otadata_partition:
        raise ValueError("No otadata partition found") # TODO Better error type

    print("Clearing boot partition...")
    esp.erase_region(offset=otadata_partition.offset, size=otadata_partition.size)

def command_ota(esp: ESPLoader, partition_table: PartitionTable, app_binary_file: str):
    otadata = read_otadata(esp, partition_table)

    partition: PartitionDefinition
    next_slot = otadata.next_slot
    partition = next(
        (p for p in partition_table if p.type == APP_TYPE and p.subtype == SUBTYPES[APP_TYPE]['ota_0'] + next_slot),
        None
    )
    if not partition:
        raise ValueError(f"Partition ota_{next_slot} not found")

    app_binary, image_metadata = load_app_binary(app_binary_file, partition)

    print(f"Writing '{image_metadata.app_description.title}' to partition '{partition.name}'...")
    write_flash(esp, addr_data=[(partition.offset, app_binary_file)])

    otadata = otadata.incremented_and_swapped(next_slot)
    write_otadata(esp, otadata)

def command_factory(esp: ESPLoader, partition_table: PartitionTable, app_binary_file: str):
    partition = next(
        (part for part in partition_table if part.type == APP_TYPE and part.subtype == SUBTYPES[APP_TYPE]['factory']),
        None
    )
    if not partition:
        partition = next(
            (part for part in partition_table if part.type == APP_TYPE and part.subtype == SUBTYPES[APP_TYPE]['ota_0']),
            None
        )
    if not partition:
        raise ValueError("No factory or OTA partition found")

    app_binary, image_metadata = load_app_binary(app_binary_file, partition)

    print(f"Writing '{image_metadata.app_description.title}' to partition '{partition.name}'...")
    write_flash(esp, addr_data=[(partition.offset, app_binary)])

    otadata_partition = next(
        (p for p in partition_table if p.type == DATA_TYPE and p.subtype == SUBTYPES[DATA_TYPE]['ota']),
        None
    )
    if otadata_partition:
        print("Erasing 'otadata' partition...")
        esp.erase_region(offset=otadata_partition.offset, size=otadata_partition.size)

def command_reflash(esp: ESPLoader, reflash_file_path: str):
    # Verify the image contains a valid partition table
    reflash_file = open(reflash_file_path, 'rb')
    reflash_file.seek(esp.BOOTLOADER_FLASH_OFFSET)
    bootloader_binary = reflash_file.read(PARTITION_TABLE_OFFSET - esp.BOOTLOADER_FLASH_OFFSET)
    try:
        bootloader_image_metadata = ImageMetadata.from_bytes(bootloader_binary)
    except (RuntimeError, ValueError):
        raise RuntimeError("Invalid bootloader in reflash image, check the input file (chip type may be incorrect)")

    if bootloader_image_metadata.header.chip_id.value != esp.IMAGE_CHIP_ID:
        raise RuntimeError(
            f"Chip ID mismatch: "
            f"attempting to flash {bootloader_image_metadata.header.chip_id.name} image "
            f"to {ChipId(esp.IMAGE_CHIP_ID).name} device"
        )

    reflash_file.seek(PARTITION_TABLE_OFFSET)
    partition_table_binary = reflash_file.read(PARTITION_TABLE_SIZE)
    try:
        partition_table = PartitionTable.from_binary(partition_table_binary)
    except RuntimeError:
        raise RuntimeError("Invalid partition table in reflash image, check the input file")

    print(f"Reflashing device with '{reflash_file_path}'...")
    print(f"New partition table:")
    print_partition_table(partition_table)
    erase_flash(esp)
    write_flash(esp, addr_data=[(0, reflash_file)])

def command_list(esp: ESPLoader, partition_table: PartitionTable):
    print_partition_table(list(part for part in partition_table if part.type == APP_TYPE or (part.type == DATA_TYPE and part.subtype == SUBTYPES[DATA_TYPE]['ota'])))

def command_info(esp: ESPLoader, partition_table: PartitionTable):
    otadata = read_otadata(esp, partition_table)

    if otadata.slot is None:
        print("OTA slot not set")
    else:
        print(f"OTA slot 'ota_{otadata.slot}' (seq={otadata.otadata.seq}, state={otadata.otadata.ota_state})")

def main(args):
    esp: ESPLoader | None = None
    if args.port:
        esp = detect_chip(args.port, baud=args.baud)
    else:
        ports = list_ports.comports()
        for port in reversed(ports):
            try:
                print(f"Serial port {port.device} (baud={args.baud})")
                esp = detect_chip(port.device, baud=args.baud)
                break
            except RuntimeError:
                pass
    if not esp:
        raise RuntimeError("No ESP found")
    esp = esp.run_stub()

    partition_table_binary = esp.read_flash(offset=PARTITION_TABLE_OFFSET, length=PARTITION_TABLE_SIZE)
    partition_table = PartitionTable.from_binary(partition_table_binary)

    if args.command == 'set_boot':
        command_set_boot(esp, partition_table=partition_table, label=args.partition)
    elif args.command == 'clear_boot':
        command_clear_boot(esp, partition_table=partition_table)
    elif args.command == 'ota':
        command_ota(esp, partition_table=partition_table, app_binary_file=args.app_binary_file)
    elif args.command == 'factory':
        command_factory(esp, partition_table=partition_table, app_binary_file=args.app_binary_file)
    elif args.command == 'reflash':
        command_reflash(esp, reflash_file_path=args.reflash_file)
    elif args.command == 'list':
        command_list(esp, partition_table=partition_table)
    elif args.command == 'info':
        command_info(esp, partition_table=partition_table)
    else:
        esp.hard_reset()
        raise ValueError(f"Invalid command {args.command}")

    esp.hard_reset()

def _main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port', help='Serial port device')
    parser.add_argument('-b', '--baud', type=int, help='Baud rate', default=ESPLoader.ESP_ROM_BAUD)

    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    # Info subcommand
    info_parser = subparsers.add_parser('info', help='Get OTA information')

    # List subcommand
    list_parser = subparsers.add_parser('list', help='List app partitions')

    # Reflash subcommand
    reflash_parser = subparsers.add_parser('reflash', help='Perform full system reflash')
    reflash_parser.add_argument('reflash_file', help='Input file containing flash image')

    # Factory subcommand
    factory_parser = subparsers.add_parser('factory', help='Perform factory flash and reset otadata')
    factory_parser.add_argument('app_binary_file', help='Input file containing app binary')

    # Ota subcommand
    ota_parser = subparsers.add_parser('ota', help='Perform OTA')
    ota_parser.add_argument('app_binary_file', help='Input file containing app binary')

    # Set Boot subcommand
    set_boot_parser = subparsers.add_parser('set_boot', help='Set boot partition')
    set_boot_parser.add_argument('partition', help='Name of the partition to set as boot')

    # Clear Boot subcommand
    clear_boot_parser = subparsers.add_parser('clear_boot', help='Clear boot partition')

    try:
        main(parser.parse_args())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    _main()