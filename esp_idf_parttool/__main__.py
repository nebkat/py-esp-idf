import argparse
import os.path
from typing import Literal

import serial.tools.list_ports as list_ports
from esptool import ESPLoader, FatalError

from esp_idf_defs.partitions import PARTITION_TABLE_SIZE, PARTITION_TABLE_OFFSET, PartitionTable, print_partition_table, \
    PartitionDefinition
from esptool.cmds import detect_chip, read_flash, write_flash, erase_region

def auto_int(x):
    return int(x, 0)

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

def command_read(esp, partition: PartitionDefinition, offset: int, length: int | None, output_file: str):
    address = partition.offset + offset
    if length is None:
        length = partition.size - offset

    if offset + length > partition.size:
        raise ValueError(f"Offset + length {offset + length} is greater than partition size {partition.size}")

    print(f"Reading partition {partition.name} (offset={address:#x}, size={length:#x})")
    read_flash(esp, address=address, size=length, output=output_file)

def command_write(esp, partition, offset, input_file):
    address = partition.offset + offset
    input_file_size = os.path.getsize(input_file)

    if offset + input_file_size > partition.size:
        raise ValueError(f"Offset + input file size {offset + input_file_size} is greater than partition size {partition.size}")

    print(f"Writing partition {partition.name} (offset={address:#x}, size={input_file_size:#x})")
    write_flash(esp, addr_data=[(address, input_file)])

def command_erase(esp, partition, offset, length):
    address = partition.offset + offset
    if length is None:
        length = partition.size - offset

    if offset + length > partition.size:
        raise ValueError(f"Offset + length {offset + length} is greater than partition size {partition.size}")

    print(f"Erasing partition {partition.name} (offset={address:#x}, size={length:#x})")
    erase_region(esp, address=address, size=length)

def command_view(esp, partition, offset, length, width, output: Literal['hex', 'str']):
    address = partition.offset + offset
    if length is None:
        length = partition.size - offset

    print(f"Viewing partition {partition.name} (offset={address:#x}, size={length:#x})")
    buffer = esp.read_flash(offset=address, length=length)
    if output == 'str':
        print(buffer.decode('utf-8', errors='replace'), flush=True)
    elif output == 'hex':
        hexdump(buffer, offset, width)
    else:
        raise ValueError(f"Invalid output type {output}")

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
    print("Partition table loaded")

    partition_table = PartitionTable.from_binary(partition_table_binary)
    print_partition_table(partition_table)

    if args.command == 'list':
        esp.hard_reset()
        return

    partition = partition_table[args.partition]

    if args.offset > partition.size:
        raise ValueError(f"Offset {args.offset} is greater than partition size {partition.size}")

    if args.command == 'read':
        command_read(esp, partition=partition, offset=args.offset, length=args.length, output_file=args.output_file)
    elif args.command == 'write':
        command_write(esp, partition=partition, offset=args.offset, input_file=args.input_file)
    elif args.command == 'erase':
        command_erase(esp, partition=partition, offset=args.offset, length=args.length)
    elif args.command == 'view':
        command_view(esp, partition=partition, offset=args.offset, length=args.length, width=args.width, output=args.output)

    esp.hard_reset()

def _main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port', help='Serial port device')
    parser.add_argument('-b', '--baud', type=int, help='Serial port baud rate', default=ESPLoader.ESP_ROM_BAUD)

    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

    # Info subcommand
    info_parser = subparsers.add_parser('info', help='Get partition information')
    info_parser.add_argument('partition', help='Name of the partition to get information about')

    # List subcommand
    list_parser = subparsers.add_parser('list', help='List partitions')
    list_parser.add_argument('--partition-type', help='Filter by partition type')
    list_parser.add_argument('--partition-subtype', help='Filter by partition subtype')
    list_parser.add_argument('--partition-name', help='Filter by partition name')

    # Read subcommand
    read_parser = subparsers.add_parser('read', help='Read partition')
    read_parser.add_argument('partition', help='Name of the partition to read')
    read_parser.add_argument('-o', '--offset', type=auto_int, help='Offset to start reading from', default=0)
    read_parser.add_argument('-l', '--length', type=auto_int, help='Number of bytes to read')
    read_parser.add_argument('output_file', help='Output file to save the partition data')

    # Write subcommand
    write_parser = subparsers.add_parser('write', help='Write partition')
    write_parser.add_argument('partition', help='Name of the partition to write')
    write_parser.add_argument('-o', '--offset', type=auto_int, help='Offset to start writing to', default=0)
    write_parser.add_argument('input_file', help='Input file with partition data')

    # Erase subcommand
    erase_parser = subparsers.add_parser('erase', help='Erase partition')
    erase_parser.add_argument('partition', help='Name of the partition to erase')
    erase_parser.add_argument('-o', '--offset', type=auto_int, help='Offset to start erasing from', default=0)
    erase_parser.add_argument('-l', '--length', type=auto_int, help='Number of bytes to erase')

    # View subcommand
    view_parser = subparsers.add_parser('view', help='View partition')
    view_parser.add_argument('partition', help='Name of the partition to view')
    view_parser.add_argument('-o', '--offset', type=auto_int, help='Offset to start viewing from', default=0)
    view_parser.add_argument('-l', '--length', type=auto_int, help='Number of bytes to view')
    view_parser.add_argument('-w', '--width', type=int, help='Width of the hexdump', default=16)
    view_parser.add_argument('--hex', action='store_const', const='hex', dest='output', help='Output as hex dump', default='hex')
    view_parser.add_argument('-s', '--string', action='store_const', const='str', dest='output', help='Output as string')

    main(parser.parse_args())

if __name__ == "__main__":
    _main()