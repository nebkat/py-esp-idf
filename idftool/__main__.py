import argparse
import os.path
import re
import sys
from typing import Optional, Literal
from zipfile import ZipFile

from esptool import ESPLoader, CHIP_DEFS, flash_size_bytes
from serial.tools import list_ports
from serial.tools.list_ports_common import ListPortInfo

from esp_idf_defs import ImageMetadata, ChipId
from esp_idf_defs.otadata import OtaDataParameters, OtaDataSelectEntry
from esp_idf_defs.partitions import PARTITION_TABLE_SIZE, PARTITION_TABLE_OFFSET, PartitionTable, print_partition_table, \
    PartitionDefinition, BOOTLOADER_TYPE, SUBTYPES, PARTITION_TABLE_TYPE, APP_TYPE, NUM_PARTITION_SUBTYPE_APP_OTA, \
    DATA_TYPE
from esptool.cmds import detect_chip, read_flash, write_flash, erase_region, merge_bin, erase_flash, detect_flash_size

PARTITION_SLICE_REGEX = re.compile(r"^(?P<partition>.+?)(?:\[(?:(?P<start>[-+]?(?:0x)?[0-9A-Fa-f]+)?(?::(?P<stop>[-+]?(?:0x)?[0-9A-Fa-f]+)?)?)?])?$")
PARTITION_OFFSET_REGEX = re.compile(r"^(?P<partition>.+?)(?:\[(?:(?P<start>[-+]?(?:0x)?[0-9A-Fa-f]+)?)?])?$")

# TODO: Use esptool version when merged
def get_port_list() -> list[str]:
    """Get the list of serial ports names with optional filters.

    For backwards compatibility, this function returns a list of port names.
    """
    return [port.device for port in _get_port_list()]


def _get_port_list() -> list[ListPortInfo]:
    ports = []
    for port in list_ports.comports():
        if sys.platform == "darwin" and port.device.endswith(
            ("Bluetooth-Incoming-Port", "wlan-debug", "cu.debug-console")
        ):
            continue
        ports.append(port)

    # Constants for sorting optimization
    ESPRESSIF_VID = 0x303A
    LINUX_DEVICE_PATTERNS = ("ttyUSB", "ttyACM")
    MACOS_DEVICE_PATTERNS = ("usbserial", "usbmodem")

    def _port_sort_key_linux(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (3, port_info.device)

        if any(pattern in port_info.device for pattern in LINUX_DEVICE_PATTERNS):
            return (2, port_info.device)

        return (1, port_info.device)

    def _port_sort_key_macos(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (3, port_info.device)

        if any(pattern in port_info.device for pattern in MACOS_DEVICE_PATTERNS):
            return (2, port_info.device)

        return (1, port_info.device)

    def _port_sort_key_windows(port_info: ListPortInfo) -> tuple[int, str]:
        if port_info.vid == ESPRESSIF_VID:
            return (2, port_info.device)

        return (1, port_info.device)

    if sys.platform == "win32":
        key_func = _port_sort_key_windows
    elif sys.platform == "darwin":
        key_func = _port_sort_key_macos
    else:
        key_func = _port_sort_key_linux

    sorted_port_info = sorted(ports, key=key_func)
    return sorted_port_info

def parse_bootloader_offset(x):
    try:
        return int(x, 0)
    except ValueError:
        if CHIP_DEFS[x] is None:
            raise argparse.ArgumentTypeError(f"Invalid bootloader offset or chip name: {x}")
        return CHIP_DEFS[x].BOOTLOADER_FLASH_OFFSET

def auto_int(x):
    return int(x, 0)

def get_esp(port: str | None, baud: int) -> ESPLoader:
    esp: ESPLoader | None = None
    if port:
        esp = detect_chip(port, baud=baud)
    else:
        ports = get_port_list()
        for port in ports:
            try:
                print(f"Serial port {port} (baud={baud})")
                esp = detect_chip(port, baud=baud)
                break
            except RuntimeError:
                pass
    if not esp:
        raise RuntimeError("No ESP found")
    esp = esp.run_stub()

    return esp

def get_partition(
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        label: str
) -> PartitionDefinition:
    try:
        try:
            address = int(label, 0)
            return next(
                (p for p in partition_table if p.offset == address),
            )
        except ValueError:
            pass
        return partition_table[label]
    except ValueError:
        if label == partition_table_entry.name:
            return partition_table_entry
        elif bootloader_entry and label == bootloader_entry.name:
            return bootloader_entry
        else:
            raise

def get_partition_slice(
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        s: str
) -> tuple[PartitionDefinition, int, int]:
    match = PARTITION_SLICE_REGEX.fullmatch(s)
    if not match:
        raise ValueError(f"Invalid partition slice format: {s}")

    partition_name = match.group("partition")
    start_str = match.group("start")
    stop_str = match.group("stop")

    partition = get_partition(partition_table, partition_table_entry, bootloader_entry, partition_name)

    start = int(start_str, 0) if start_str else 0
    if start < 0:
        start += partition.size

    if stop_str is None:
        stop = partition.size
    else:
        stop = int(stop_str, 0)
        if stop_str[0] == '+':
            stop = start + stop
        if stop < 0:
            stop += partition.size

    if start < 0 or stop < 0 or start > partition.size or stop > partition.size or start > stop:
        raise ValueError(f"Invalid slice range [{start:#x}:{stop:#x}] for partition {partition_name} of size {partition.size:#x}")

    return partition, partition.offset + start, stop - start

def get_partition_address(
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        s: str
) -> tuple[PartitionDefinition, int]:
    match = PARTITION_OFFSET_REGEX.fullmatch(s)
    if not match:
        raise ValueError(f"Invalid partition offset format: {s}")

    partition_name = match.group("partition")
    start_str = match.group("start")

    partition = get_partition(partition_table, partition_table_entry, bootloader_entry, partition_name)

    start = int(start_str, 0) if start_str else 0
    if start < 0:
        start += partition.size

    if start < 0 or start > partition.size:
        raise ValueError(f"Invalid offset [{start:#x}] for partition {partition_name} of size {partition.size:#x}")

    return partition, partition.offset + start

def hexdump(data: bytes, start = 0, width = 16):
    def to_printable_ascii(byte):
        return chr(byte) if 32 <= byte <= 126 else "."

    # If start is not aligned, print an empty row with padding
    misalignment = start % width
    start -= misalignment

    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + width - misalignment]
        hex_values = "-- " * misalignment +  " ".join(f"{byte:02x}" for byte in chunk) + " " + "-- " * (width - len(chunk) - misalignment)
        ascii_values = "-" * misalignment + "".join(to_printable_ascii(byte) for byte in chunk) + "-" * (width - len(chunk) - misalignment)
        print(f"0x{start + offset:08x}  {hex_values} |{ascii_values}|")
        offset += width - misalignment
        misalignment = 0

def read_otadata(esp: ESPLoader, partition_table: PartitionTable) -> tuple[PartitionDefinition, OtaDataParameters]:
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

    return otadata_partition, OtaDataParameters(otadata, a_or_b, ota_app_count)

def write_otadata(esp: ESPLoader, partition: PartitionDefinition, otadata: OtaDataParameters):
    esp.flash_begin(
        size=OtaDataSelectEntry.SIZE,
        offset=partition.offset + (0 if otadata.a_or_b == 'a' else esp.FLASH_SECTOR_SIZE)
    )
    esp.flash_block(data=otadata.otadata.to_bytes(), seq=0)
    esp.flash_finish()

def validate_app_binary(esp: ESPLoader, app_binary: bytes) -> tuple[bytes, ImageMetadata]:
    try:
        image_metadata = ImageMetadata.from_bytes(app_binary, app_required=True)
    except ValueError as e:
        raise RuntimeError(f"Invalid application binary: {e}")

    if image_metadata.header.chip_id.value != esp.IMAGE_CHIP_ID:
        raise RuntimeError(
            f"Chip ID mismatch: "
            f"attempting to flash {image_metadata.header.chip_id.name} image "
            f"to {ChipId(esp.IMAGE_CHIP_ID).name} device"
        )

    return app_binary, image_metadata

def load_app_binary(esp: ESPLoader, app_binary_file: str, partition: PartitionDefinition) -> tuple[bytes, ImageMetadata]:
    app_binary_size = os.path.getsize(app_binary_file)
    if app_binary_size > partition.size:
        raise RuntimeError(
            f"Application binary size '{app_binary_size}' is greater than partition size {partition.size}")

    app_binary = open(app_binary_file, 'rb').read()
    return validate_app_binary(esp, app_binary)

def command_read(
        esp: ESPLoader,
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        label: str,
        output_file: str
):
    partition, address, length = get_partition_slice(partition_table, partition_table_entry, bootloader_entry, label)
    print(f"Reading partition {partition.name} (offset={address:#x}, size={length:#x})")
    read_flash(esp, address=address, size=length, output=output_file)

def command_write(
        esp: ESPLoader,
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        files: list[str]
):
    addr_data = []
    for partition_name, input_file in list(zip(files[::2], files[1::2])):
        partition, address = get_partition_address(partition_table, partition_table_entry, bootloader_entry, partition_name)
        input_file_size = os.path.getsize(input_file)
        if input_file_size > partition.size:
            raise ValueError(f"Input file {input_file} size {input_file_size:#x} exceeds partition {partition.name} size {partition.size:#x}")
        addr_data.append((address, input_file))
        print(f"Writing file {input_file} (size={input_file_size:#x}) to partition {partition.name} (offset={address:#x}, size={partition.size:#x})")

    write_flash(
        esp=esp,
        addr_data=addr_data,
        flash_size='detect'
    )

def command_erase(
        esp: ESPLoader,
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        label: str
):
    partition, address, length = get_partition_slice(partition_table, partition_table_entry, bootloader_entry, label)

    print(f"Erasing partition {partition.name} (offset={address:#x}, size={length:#x})")
    erase_region(esp, address=address, size=length)

def command_view(
        esp: ESPLoader,
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        label: str,
        output: Literal['str', 'hex'],
        width: int
):
    partition, address, length = get_partition_slice(partition_table, partition_table_entry, bootloader_entry, label)

    print(f"Viewing partition {partition.name} (offset={address:#x}, size={length:#x})")
    buffer = esp.read_flash(offset=address, length=length)
    if output == 'str':
        print(buffer.decode('utf-8', errors='replace'), flush=True)
    elif output == 'hex':
        hexdump(buffer, address - partition.offset, width)
    else:
        raise ValueError(f"Invalid output type {output}")

def command_merge_bin(
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        files: list[str],
        flash_partition_table: bool,
        output_format: Literal['raw', 'uf2', 'hex'],
        output_file: str
):
    addr_data = []
    for partition_name, input_file in list(zip(files[::2], files[1::2])):
        partition, address = get_partition_address(partition_table, partition_table_entry, bootloader_entry, partition_name)
        input_file_size = os.path.getsize(input_file)
        if input_file_size > partition.size:
            raise ValueError(
                f"Input file {input_file} size {input_file_size:#x} exceeds partition {partition.name} size {partition.size:#x}")
        addr_data.append((address, input_file))
        print(f"Merging file {input_file} (size={input_file_size:#x}) to partition {partition.name} (offset={address:#x}, size={partition.size:#x})")

    # Add partition table if requested
    if flash_partition_table:
        partition_table_binary = partition_table.to_binary()
        addr_data.append((partition_table_entry.offset, partition_table_binary))

    merge_bin(
        addr_data=addr_data,
        flash_freq="keep",
        flash_mode="keep",
        flash_size="keep",
        chip='esp32', # Does not matter since we are keeping all flash parameters
        output=output_file,
        output_format=output_format,
        partition_table=partition_table
    )

def command_create_bundle(
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        files: list[str],
        flash_partition_table: bool,
        output_file: str
):
    with ZipFile(output_file, 'w') as zf:
        # Add specified partition files
        for partition_name, input_file in list(zip(files[::2], files[1::2])):
            partition = get_partition(partition_table, partition_table_entry, bootloader_entry, partition_name)
            input_file_size = os.path.getsize(input_file)
            if input_file_size > partition.size:
                raise ValueError(
                    f"Input file {input_file} size {input_file_size:#x} exceeds partition {partition.name} size {partition.size:#x}")
            zf.write(input_file, arcname=f"{partition.name}.bin")
            print(f"Adding file {input_file} (size={input_file_size:#x}) to bundle as partition {partition.name} (offset={partition.offset:#x}, size={partition.size:#x})")

        # Add empty files for erased partitions
        # for partition_name in args.erase:
        #     partition = get_partition(partition_table, partition_table_entry, bootloader_entry, partition_name)
        #     zf.writestr(f"{partition.name}.bin", bytes(partition.size))
        #     print(f"Adding empty file to bundle for erased partition {partition.name} (offset={partition.offset:#x}, size={partition.size:#x})")

        # Add partition table if requested
        if flash_partition_table:
            zf.writestr("partition_table.csv", partition_table.to_csv())
            print(f"Adding partition table CSV to bundle")

def check_write_bundle_has_partition_table(file: str) -> bool:
    with ZipFile(file, 'r') as zf:
        return any(m == 'partition_table.csv' for m in zf.namelist())

def command_write_bundle(
        esp: ESPLoader,
        partition_table: PartitionTable,
        partition_table_entry: PartitionDefinition,
        bootloader_entry: Optional[PartitionDefinition],
        input_file: str
):
    with ZipFile(input_file, 'r') as zf:
        # Flash files
        addr_data = []
        for member in filter(lambda m: m.endswith('.bin'), zf.namelist()):
            partition_name = member[:-4]  # Remove .bin extension
            partition = get_partition(partition_table, partition_table_entry, bootloader_entry, partition_name)
            data = zf.read(member)
            if len(data) > partition.size:
                raise ValueError(f"Input file {member.name} size {len(data):#x} exceeds partition {partition.name} size {partition.size:#x}")

            if partition.type == APP_TYPE:
                validate_app_binary(esp, data)

            print(f"Writing partition {partition.name} (offset={partition.offset:#x}, size={partition.size:#x}) from bundle")
            addr_data.append((partition.offset, data))

        # Flash partition table if present
        if any(m == 'partition_table.csv' for m in zf.namelist()):
            partition = next(
                (e for e in partition_table if e.type == PARTITION_TABLE_TYPE and e.subtype == SUBTYPES[e.type]['primary'])
            )
            print(f"Writing partition table (offset={partition.offset:#x}, size={partition.size:#x}) from bundle")
            addr_data.append((partition.offset, partition_table.to_binary()))

        # Perform write
        write_flash(
            esp=esp,
            addr_data=addr_data,
            flash_size='detect',
        )

def command_get_boot(esp: ESPLoader, partition_table: PartitionTable):
    _, otadata = read_otadata(esp, partition_table)

    if otadata.slot is None:
        print("OTA slot not set")
    else:
        print(f"OTA slot 'ota_{otadata.slot}' (seq={otadata.otadata.seq}, state={otadata.otadata.ota_state})")

def command_set_boot(esp: ESPLoader, partition_table: PartitionTable, label: str):
    otadata_partition, otadata = read_otadata(esp, partition_table)

    partition = partition_table[label]
    if partition.type != APP_TYPE:
        raise ValueError(f"Partition {label} is not an app partition")
    if partition.subtype < SUBTYPES[APP_TYPE]['ota_0'] or partition.subtype > SUBTYPES[APP_TYPE]['ota_15']:
        raise ValueError(f"Partition {label} is not an OTA partition")
    ota_slot = partition.subtype & 0x0F

    print(f"Setting boot partition to '{partition.name}'...")
    otadata = otadata.incremented_and_swapped(ota_slot)
    write_otadata(esp, otadata_partition, otadata)

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
    otadata_partition, otadata = read_otadata(esp, partition_table)

    partition: PartitionDefinition
    next_slot = otadata.next_slot
    partition = next(
        (p for p in partition_table if p.type == APP_TYPE and p.subtype == SUBTYPES[APP_TYPE]['ota_0'] + next_slot),
        None
    )
    if not partition:
        raise ValueError(f"Partition ota_{next_slot} not found")

    app_binary, image_metadata = load_app_binary(esp, app_binary_file, partition)

    print(f"Writing '{image_metadata.app_description.title}' to partition '{partition.name}'...")
    write_flash(esp=esp, addr_data=[(partition.offset, app_binary_file)])

    print(f"Setting boot partition to 'ota_{next_slot}'...")
    otadata = otadata.incremented_and_swapped(next_slot)
    write_otadata(esp, otadata_partition, otadata)

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

    app_binary, image_metadata = load_app_binary(esp, app_binary_file, partition)

    print(f"Writing '{image_metadata.app_description.title}' to partition '{partition.name}'...")
    write_flash(esp=esp, addr_data=[(partition.offset, app_binary)])

    otadata_partition = next(
        (p for p in partition_table if p.type == DATA_TYPE and p.subtype == SUBTYPES[DATA_TYPE]['ota']),
        None
    )
    if otadata_partition:
        print("Erasing 'otadata' partition...")
        esp.erase_region(offset=otadata_partition.offset, size=otadata_partition.size)

def command_reflash(esp: ESPLoader, bootloader_entry: PartitionDefinition, reflash_file_path: str):
    # Verify the image contains a valid bootloader
    reflash_file = open(reflash_file_path, 'rb')
    reflash_file.seek(bootloader_entry.offset)
    bootloader_binary = reflash_file.read(bootloader_entry.size)
    try:
        bootloader_image_metadata = ImageMetadata.from_bytes(bootloader_binary)
    except (RuntimeError, ValueError) as e:
        raise RuntimeError("Invalid bootloader in reflash image, check the input file (chip type may be incorrect)")\
            from e

    if bootloader_image_metadata.header.chip_id.value != esp.IMAGE_CHIP_ID:
        raise RuntimeError(
            f"Chip ID mismatch: "
            f"attempting to flash {bootloader_image_metadata.header.chip_id.name} image "
            f"to {ChipId(esp.IMAGE_CHIP_ID).name} device"
        )

    reflash_data: bytes
    with open(reflash_file_path, 'rb') as reflash_file:
        reflash_file.seek(esp.BOOTLOADER_FLASH_OFFSET)
        reflash_data = reflash_file.read()

    print(f"Reflashing device with '{reflash_file_path}'...")
    erase_flash(esp)
    write_flash(
        esp=esp,
        addr_data=[(esp.BOOTLOADER_FLASH_OFFSET, reflash_data)],
        flash_size='detect',
    )

def main(args):
    if args.command == 'devices':
        devices = _get_port_list()
        for d in devices:
            print(f"{d.device} || {d.description} || {d.hwid}")
        return

    # Connect to ESP device if required
    requires_esp = args.command not in ['list', 'merge-bin', 'create-bundle'] or not args.partition_table_file
    esp = get_esp(port=args.port, baud=args.baud) if requires_esp else None
    if not args.primary_bootloader_offset and esp:
        args.primary_bootloader_offset = esp.BOOTLOADER_FLASH_OFFSET

    # Load partition table
    if args.command == 'reflash':
        with open(args.reflash_file, 'rb') as f:
            f.seek(args.partition_table_offset)
            partition_table_binary = f.read(args.partition_table_size)
            partition_table = PartitionTable.from_binary(partition_table_binary)
    elif args.partition_table_file:
        with open(args.partition_table_file, 'rb') as f:
            partition_table = PartitionTable.from_file(
                f,
                partition_table_offset=args.partition_table_offset,
                primary_bootloader_offset=args.primary_bootloader_offset,
                recovery_bootloader_offset=args.recovery_bootloader_offset
            )[0]
    elif args.command == 'write-bundle' and check_write_bundle_has_partition_table(args.input_file):
        with ZipFile(args.input_file, 'r') as tar:
            partition_table_file = tar.read('partition_table.csv')
            if not partition_table_file:
                raise RuntimeError("Partition table could not be loaded from bundle")
            partition_table = PartitionTable.from_csv(
                partition_table_file.decode('utf-8'),
                partition_table_offset=args.partition_table_offset,
                primary_bootloader_offset=args.primary_bootloader_offset,
                recovery_bootloader_offset=args.recovery_bootloader_offset
            )
    else:
        try:
            partition_table_binary = esp.read_flash(offset=args.partition_table_offset, length=args.partition_table_size)
            partition_table = PartitionTable.from_binary(partition_table_binary)
        except RuntimeError as e:
            raise RuntimeError("Partition table could not be loaded") from e

    # Print partition table
    print_partition_table(partition_table, esp)

    if esp:
        flash_size_str = detect_flash_size(esp)
        flash_size = flash_size_bytes(flash_size_str)
        partition_table.verify_size_fits(flash_size)

    # Add virtual partition table entry if not present
    partition_table_entry = next(
        (e for e in partition_table if e.type == PARTITION_TABLE_TYPE and e.subtype == SUBTYPES[e.type]['primary']),
        PartitionDefinition.default_partition_table(
            offset=args.partition_table_offset,
            size=args.partition_table_size
        )
    )

    # Add virtual bootloader partition if not present and bootloader offsets are provided
    bootloader_entry = next(
        (e for e in partition_table if e.type == BOOTLOADER_TYPE and e.subtype == SUBTYPES[e.type]['primary']),
        PartitionDefinition.default_bootloader(
            offset=args.primary_bootloader_offset,
            size=args.partition_table_offset - args.primary_bootloader_offset
        ) if args.primary_bootloader_offset is not None else None
    )

    if args.command == 'list':
        pass
    elif args.command == 'read':
        command_read(
            esp=esp,
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            label=args.partition,
            output_file=args.output_file
        )
    elif args.command == 'write':
        command_write(
            esp=esp,
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            files=args.files
        )
    elif args.command == 'erase':
        command_erase(
            esp=esp,
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            label=args.partition
        )
    elif args.command == 'view':
        command_view(
            esp=esp,
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            label=args.partition,
            output=args.output,
            width=args.width
        )
    elif args.command == 'merge-bin':
        command_merge_bin(
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            files=args.files,
            flash_partition_table=args.flash_partition_table,
            output_format=args.format,
            output_file=args.output_file
        )
    elif args.command == 'create-bundle':
        command_create_bundle(
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            files=args.files,
            flash_partition_table=args.flash_partition_table,
            output_file=args.output_file
        )
    elif args.command == 'write-bundle':
        command_write_bundle(
            esp=esp,
            partition_table=partition_table,
            partition_table_entry=partition_table_entry,
            bootloader_entry=bootloader_entry,
            input_file=args.input_file
        )
    elif args.command == 'get_boot':
        command_get_boot(esp=esp, partition_table=partition_table)
    elif args.command == 'set_boot':
        command_set_boot(esp=esp, partition_table=partition_table, label=args.partition)
    elif args.command == 'clear_boot':
        command_clear_boot(esp=esp, partition_table=partition_table)
    elif args.command == 'ota':
        command_ota(esp=esp, partition_table=partition_table, app_binary_file=args.app_binary_file)
    elif args.command == 'factory':
        command_factory(esp=esp, partition_table=partition_table, app_binary_file=args.app_binary_file)
    elif args.command == 'reflash':
        command_reflash(esp=esp, bootloader_entry=bootloader_entry, reflash_file_path=args.reflash_file)

    if esp and not args.no_reset: esp.hard_reset()

def _main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port', help='Serial port device')
    parser.add_argument('-b', '--baud', type=int, help='Serial port baud rate', default=ESPLoader.ESP_ROM_BAUD)
    parser.add_argument('--no-reset', action='store_true', help='Do not reset the chip after operations')

    parser.add_argument('--partition-table-file', help='Path to partition table CSV or binary file to use instead of reading from device')
    parser.add_argument('--partition-table-offset', type=auto_int, help='Partition table offset (where to read partition table from flash, or where to place when loading partition table from CSV)', default=PARTITION_TABLE_OFFSET)
    parser.add_argument('--partition-table-size', type=auto_int, help='Partition table size', default=PARTITION_TABLE_SIZE)
    parser.add_argument('--primary-bootloader-offset', type=parse_bootloader_offset, help='Primary bootloader offset or chip type e.g. esp32s3 (used when loading partition table from CSV)')
    parser.add_argument('--recovery-bootloader-offset', type=auto_int, help='Recovery bootloader offset (used when loading partition table from CSV)')

    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    # Devices subcommand
    devices_parser = subparsers.add_parser('devices', help='Device list')

    # List subcommand
    list_parser = subparsers.add_parser('list', help='List partitions')
    list_parser.add_argument('--partition-type', help='Filter by partition type')
    list_parser.add_argument('--partition-subtype', help='Filter by partition subtype')
    list_parser.add_argument('--partition-name', help='Filter by partition name')

    # Read subcommand
    read_parser = subparsers.add_parser('read', help='Read partition')
    read_parser.add_argument('partition', help='Name of the partition to read')
    read_parser.add_argument('output-file', help='Output file to save the partition data')

    # Write subcommand
    write_parser = subparsers.add_parser('write', help='Write partitions')
    write_parser.add_argument(
        'files',
        nargs='+',
        metavar=('PARTITION', 'FILENAME'),
        help='Partition and filename pairs'
    )

    # Erase subcommand
    erase_parser = subparsers.add_parser('erase', help='Erase partition')
    erase_parser.add_argument('partition', help='Name of the partition to erase')

    # View subcommand
    view_parser = subparsers.add_parser('view', help='View partition')
    view_parser.add_argument('partition', help='Name of the partition to view')
    view_parser.add_argument('-w', '--width', type=int, help='Width of the hexdump', default=16)
    view_parser.add_argument('--hex', action='store_const', const='hex', dest='output', help='Output as hex dump', default='hex')
    view_parser.add_argument('-s', '--string', action='store_const', const='str', dest='output', help='Output as string')

    # Merge binaries subcommand
    merge_bin_parser = subparsers.add_parser('merge-bin', help='Merge binaries into a single image')
    merge_bin_parser.add_argument('-o', '--output', help='Output filename', dest='output_file', required=True)
    merge_bin_parser.add_argument('-f', '--format', help='Output format', choices=['raw', 'uf2', 'hex'], default='raw')
    merge_bin_parser.add_argument('--flash-partition-table', action='store_true', help='Include partition table in the bundle')
    merge_bin_parser.add_argument(
        'files',
        nargs='+',
        metavar='PARTITION FILENAME',
        help='Partition and filename pairs'
    )

    # Write bundle subcommand
    write_bundle_parser = subparsers.add_parser('write-bundle', help='Write a ZIP bundle of partition binaries')
    write_bundle_parser.add_argument('input_file', help='Input ZIP filename')

    # Create bundle subcommand
    create_bundle_parser = subparsers.add_parser('create-bundle', help='Create a ZIP bundle of partition binaries')
    create_bundle_parser.add_argument('-o', '--output', help='Output ZIP filename', dest='output_file', required=True)
    create_bundle_parser.add_argument('--flash-partition-table', action='store_true', help='Include partition table in the bundle')
    create_bundle_parser.add_argument(
        'files',
        nargs='+',
        metavar='PARTITION FILENAME',
        help='Partition and filename pairs'
    )

    # Reflash subcommand
    reflash_parser = subparsers.add_parser('reflash', help='Perform full system reflash')
    reflash_parser.add_argument('reflash_file', help='Input file containing flash image')

    # Factory subcommand
    factory_parser = subparsers.add_parser('factory', help='Perform factory flash and reset otadata')
    factory_parser.add_argument('app_binary_file', help='Input file containing app binary')

    # Ota subcommand
    ota_parser = subparsers.add_parser('ota', help='Perform OTA')
    ota_parser.add_argument('app_binary_file', help='Input file containing app binary')

    # Get Boot subcommand
    get_boot_parser = subparsers.add_parser('get_boot', help='Get boot partition')

    # Set Boot subcommand
    set_boot_parser = subparsers.add_parser('set_boot', help='Set boot partition')
    set_boot_parser.add_argument('partition', help='Name of the partition to set as boot')

    # Clear Boot subcommand
    clear_boot_parser = subparsers.add_parser('clear_boot', help='Clear boot partition')

    main(parser.parse_args())

if __name__ == "__main__":
    _main()