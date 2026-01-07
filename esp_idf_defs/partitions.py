#
# Extract from ESP32 partition table generation tool
#
# Converts partition tables to/from CSV and binary formats.
#
# See https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/partition-tables.html
# for explanation of partition table structure and uses.
#
# SPDX-FileCopyrightText: 2016-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import binascii
import codecs
import hashlib
import os
import re
import struct
from typing import List, Optional

from esptool import ESPLoader

from esp_idf_defs.app_description import AppDescription

MAX_PARTITION_LENGTH = 0xC00  # 3K for partition data (96 entries) leaves 1K in a 4K sector for signature
MD5_PARTITION_BEGIN = b'\xeb\xeb' + b'\xff' * 14  # The first 2 bytes are like magic numbers for MD5 sum
PARTITION_TABLE_SIZE = 0x1000  # Size of partition table
PARTITION_TABLE_OFFSET = 0x8000

MIN_PARTITION_SUBTYPE_APP_OTA = 0x10
NUM_PARTITION_SUBTYPE_APP_OTA = 16
MIN_PARTITION_SUBTYPE_APP_TEE = 0x30
NUM_PARTITION_SUBTYPE_APP_TEE = 2

SECURE_NONE = None
SECURE_V1 = 'v1'
SECURE_V2 = 'v2'

__version__ = '1.5'

APP_TYPE = 0x00
DATA_TYPE = 0x01
BOOTLOADER_TYPE = 0x02
PARTITION_TABLE_TYPE = 0x03

TYPES = {
    'bootloader': BOOTLOADER_TYPE,
    'partition_table': PARTITION_TABLE_TYPE,
    'app': APP_TYPE,
    'data': DATA_TYPE,
}

NVS_RW_MIN_PARTITION_SIZE = 0x3000


def get_ptype_as_int(ptype):
    """ Convert a string which might be numeric or the name of a partition type to an integer"""
    try:
        return TYPES[ptype]
    except KeyError:
        try:
            return int(ptype, 0)
        except TypeError:
            return ptype


# Keep this map in sync with esp_partition_subtype_t enum in esp_partition.h
SUBTYPES = {
    BOOTLOADER_TYPE: {
        'primary': 0x00,
        'ota': 0x01,
        'recovery': 0x02,
    },
    PARTITION_TABLE_TYPE: {
        'primary': 0x00,
        'ota': 0x01,
    },
    APP_TYPE: {
        'factory': 0x00,
        'test': 0x20,
    },
    DATA_TYPE: {
        'ota': 0x00,
        'phy': 0x01,
        'nvs': 0x02,
        'coredump': 0x03,
        'nvs_keys': 0x04,
        'efuse': 0x05,
        'undefined': 0x06,
        'esphttpd': 0x80,
        'fat': 0x81,
        'spiffs': 0x82,
        'littlefs': 0x83,
        'tee_ota': 0x90,
    },
}


def get_subtype_as_int(ptype, subtype):
    """ Convert a string which might be numeric or the name of a partition subtype to an integer"""
    try:
        return SUBTYPES[get_ptype_as_int(ptype)][subtype]
    except KeyError:
        try:
            return int(subtype, 0)
        except TypeError:
            return subtype


ALIGNMENT = {
    APP_TYPE: 0x10000,
    DATA_TYPE: 0x1000,
    BOOTLOADER_TYPE: 0x1000,
    PARTITION_TABLE_TYPE: 0x1000,
}


def get_alignment_offset_for_type(ptype):
    return ALIGNMENT.get(ptype, ALIGNMENT[DATA_TYPE])


def get_alignment_size_for_type(ptype, secure: Optional[str] = SECURE_NONE):
    if ptype == APP_TYPE:
        if secure == SECURE_V1:
            # For secure boot v1 case, app partition must be 64K aligned
            # signature block (68 bytes) lies at the very end of 64K block
            return 0x10000
        elif secure == SECURE_V2:
            # For secure boot v2 case, app partition must be 4K aligned
            # signature block (4K) is kept after padding the unsigned image to 64K boundary
            return 0x1000
        else:
            # For no secure boot enabled case, app partition must be 4K aligned (min. flash erase size)
            return 0x1000
    # No specific size alignment requirement as such
    return 0x1


def get_partition_type(ptype):
    if ptype == 'app':
        return APP_TYPE
    if ptype == 'data':
        return DATA_TYPE
    if ptype == 'bootloader':
        return BOOTLOADER_TYPE
    if ptype == 'partition_table':
        return PARTITION_TABLE_TYPE
    raise InputError('Invalid partition type')

def print_partition_table(partition_table: List[PartitionDefinition], esp: Optional[ESPLoader] = None):
    def addr_format(a, include_sizes):
        if include_sizes:
            for (val, suffix) in [(0x100000, 'M'), (0x400, 'K')]:
                if a % val == 0:
                    return f'{a // val}{suffix}'
        return f'0x{a:x}'

    def lookup_keyword(t, keywords):
        for k, v in keywords.items():
            if t == v:
                return k
        return f'{t}'

    has_flags = any(part.get_flags_list() for part in partition_table)

    # Pretty print partition info
    # 1) Gather all rows of strings
    rows = []

    # header row
    header = ["Name", "Type", "Subtype", "Offset", "Size"]
    if has_flags:
        header.append("Flags")
    if esp:
        header.append("App description")
    rows.append(header)

    # each data row
    for part in partition_table:
        cells = []
        # basic fields
        name_str = part.name
        type_str = lookup_keyword(part.type, TYPES)
        subtype_str = lookup_keyword(part.subtype, SUBTYPES.get(part.type, {}))
        offset_str = addr_format(part.offset, False)
        size_str = addr_format(part.size, True)
        cells.extend([name_str, type_str, subtype_str, offset_str, size_str])

        # optional flags
        if has_flags:
            flag_str = ":".join(f for f in part.get_flags_list())
            cells.append(flag_str)

        # optional app description
        if esp:
            raw = esp.read_flash(part.offset + AppDescription.FIRMWARE_BINARY_OFFSET,
                                 AppDescription.SIZE)
            desc = AppDescription.from_bytes_or_none(raw)
            cells.append(desc.title if desc else "")

        rows.append(cells)

    # 2) Compute max width for each column
    #    zip(*rows) groups together all values of each column
    col_widths = [max(len(cell) for cell in col) for col in zip(*rows)]

    # 3) Print the table
    #    build a reusable format string like "| {:<w0} | {:<w1} | … |"
    fmt_cells = []
    for i, w in enumerate(col_widths):
        # left‑align text; you can switch to > for right‑align numeric columns if you like
        fmt_cells.append(f" {{:<{w}}} ")
    row_fmt = "|" + "|".join(fmt_cells) + "|"

    # separator line, using dashes
    sep = "|" + "|".join("-" * (w + 2) for w in col_widths) + "|"

    # output
    print(row_fmt.format(*rows[0]))
    print(sep)
    for data_row in rows[1:]:
        print(row_fmt.format(*data_row))

def get_encoding(first_bytes):
    """Detect the encoding by checking for BOM (Byte Order Mark)"""
    BOMS = {
        codecs.BOM_UTF8: 'utf-8-sig',
        codecs.BOM_UTF16_LE: 'utf-16',
        codecs.BOM_UTF16_BE: 'utf-16',
        codecs.BOM_UTF32_LE: 'utf-32',
        codecs.BOM_UTF32_BE: 'utf-32',
    }
    for bom, encoding in BOMS.items():
        if first_bytes.startswith(bom):
            return encoding
    return 'utf-8'

class PartitionTable(list):
    def __init__(self):
        super(PartitionTable, self).__init__(self)

    @classmethod
    def from_file(cls, f, partition_table_offset: int = PARTITION_TABLE_OFFSET, primary_bootloader_offset: Optional[int] = None, recovery_bootloader_offset: Optional[int] = None):
        bin_data = f.read()
        data_is_binary = bin_data[0:2] == PartitionDefinition.MAGIC_BYTES
        if data_is_binary:
            return cls.from_binary(bin_data), True

        str_data = bin_data.decode(get_encoding(bin_data))
        return cls.from_csv(str_data, partition_table_offset, primary_bootloader_offset, recovery_bootloader_offset), False

    @classmethod
    def from_csv(cls, csv_contents, partition_table_offset: int = PARTITION_TABLE_OFFSET, primary_bootloader_offset: Optional[int] = None, recovery_bootloader_offset: Optional[int] = None):
        res = PartitionTable()
        lines = csv_contents.splitlines()

        def expand_vars(f):
            f = os.path.expandvars(f)
            m = re.match(r'(?<!\\)\$([A-Za-z_][A-Za-z0-9_]*)', f)
            if m:
                raise InputError("unknown variable '%s'" % m.group(1))
            return f

        for line_no in range(len(lines)):
            line = expand_vars(lines[line_no]).strip()
            if line.startswith('#') or len(line) == 0:
                continue
            try:
                res.append(PartitionDefinition.from_csv(line, line_no + 1, partition_table_offset, primary_bootloader_offset, recovery_bootloader_offset))
            except InputError as err:
                raise InputError(
                    'Error at line %d: %s'
                    % (line_no + 1, err)
                )
            except Exception:
                raise

        # fix up missing offsets & negative sizes
        last_end = partition_table_offset + PARTITION_TABLE_SIZE  # first offset after partition table
        for e in res:
            is_primary_bootloader = e.type == BOOTLOADER_TYPE and e.subtype == SUBTYPES[e.type]['primary']
            is_primary_partition_table = e.type == PARTITION_TABLE_TYPE and e.subtype == SUBTYPES[e.type]['primary']
            if is_primary_bootloader or is_primary_partition_table:
                # They do not participate in the restoration of missing offsets
                continue
            if e.offset is not None and e.offset < last_end:
                if e == res[0]:
                    raise InputError(
                        'CSV Error at line %d: Partitions overlap. Partition sets offset 0x%x. '
                        'But partition table occupies the whole sector 0x%x. '
                        'Use a free offset 0x%x or higher.' % (e.line_no, e.offset, partition_table_offset, last_end)
                    )
                else:
                    raise InputError(
                        'CSV Error at line %d: Partitions overlap. Partition sets offset 0x%x. '
                        'Previous partition ends 0x%x' % (e.line_no, e.offset, last_end)
                    )
            if e.offset is None:
                pad_to = get_alignment_offset_for_type(e.type)
                if last_end % pad_to != 0:
                    last_end += pad_to - (last_end % pad_to)
                e.offset = last_end
            if e.size < 0:
                e.size = -e.size - e.offset
            last_end = e.offset + e.size

        return res

    def __getitem__(self, item) -> PartitionDefinition:
        """Allow partition table access via name as well as by
        numeric index."""
        if isinstance(item, str):
            for x in self:
                if x.name == item:
                    return x
            raise ValueError("No partition entry named '%s'" % item)
        else:
            return super(PartitionTable, self).__getitem__(item)

    def find_by_type(self, ptype, subtype):
        """Return a partition by type & subtype, returns
        None if not found"""
        # convert ptype & subtypes names (if supplied this way) to integer values
        ptype = get_ptype_as_int(ptype)
        subtype = get_subtype_as_int(ptype, subtype)

        for p in self:
            if p.type == ptype and p.subtype == subtype:
                yield p
        return

    def find_by_name(self, name):
        for p in self:
            if p.name == name:
                return p
        return None

    def verify(self, partition_table_offset: Optional[int] = None, secure: Optional[str] = SECURE_NONE):
        # verify each partition individually
        for p in self:
            p.verify(secure)

        # check on duplicate name
        names = [p.name for p in self]
        duplicates = set(n for n in names if names.count(n) > 1)

        # print sorted duplicate partitions by name
        if len(duplicates) != 0:
            raise InputError('Partition names must be unique')

        # check for overlaps
        last = None
        for p in sorted(self, key=lambda x: x.offset):
            if partition_table_offset is not None and p.offset < partition_table_offset + PARTITION_TABLE_SIZE:
                is_primary_bootloader = p.type == BOOTLOADER_TYPE and p.subtype == SUBTYPES[p.type]['primary']
                is_primary_partition_table = p.type == PARTITION_TABLE_TYPE and p.subtype == SUBTYPES[p.type]['primary']
                if not (is_primary_bootloader or is_primary_partition_table):
                    raise InputError(
                        'Partition offset 0x%x is below 0x%x' % (p.offset, partition_table_offset + PARTITION_TABLE_SIZE)
                    )
            if last is not None and p.offset < last.offset + last.size:
                raise InputError(
                    'Partition at 0x%x overlaps 0x%x-0x%x' % (p.offset, last.offset, last.offset + last.size - 1)
                )
            last = p

        # check that otadata should be unique
        otadata_duplicates = [p for p in self if p.type == TYPES['data'] and p.subtype == SUBTYPES[DATA_TYPE]['ota']]
        if len(otadata_duplicates) > 1:
            raise InputError(
                'Found multiple otadata partitions. Only one partition can be defined with '
                'type="data"(1) and subtype="ota"(0).'
            )

        if len(otadata_duplicates) == 1 and otadata_duplicates[0].size != 0x2000:
            raise InputError('otadata partition must have size = 0x2000')

        # Above checks but for TEE otadata
        otadata_duplicates = [
            p for p in self if p.type == TYPES['data'] and p.subtype == SUBTYPES[DATA_TYPE]['tee_ota']
        ]
        if len(otadata_duplicates) > 1:
            raise InputError(
                'Found multiple TEE otadata partitions. Only one partition can be defined with '
                'type="data"(1) and subtype="tee_ota"(0x90).'
            )

        if len(otadata_duplicates) == 1 and otadata_duplicates[0].size != 0x2000:
            raise InputError('TEE otadata partition must have size = 0x2000')


    def flash_size(self):
        """Return the size that partitions will occupy in flash
        (ie the offset the last partition ends at)
        """
        try:
            last = sorted(self, reverse=True)[0]
        except IndexError:
            return 0  # empty table!
        return last.offset + last.size

    def verify_size_fits(self, flash_size_bytes: int) -> None:
        """Check that partition table fits into the given flash size.
        Raises InputError otherwise.
        """
        table_size = self.flash_size()
        if flash_size_bytes < table_size:
            mb = 1024 * 1024
            raise InputError(
                'Partitions tables occupies %.1fMB of flash (%d bytes) which does not fit in available '
                "flash size %dMB."
                % (table_size / mb, table_size, flash_size_bytes / mb)
            )

    @classmethod
    def from_binary(cls, b, md5sum=True):
        md5 = hashlib.md5()
        result = cls()
        for o in range(0, len(b), 32):
            data = b[o: o + 32]
            if len(data) != 32:
                raise InputError('Partition table length must be a multiple of 32 bytes')
            if data == b'\xff' * 32:
                return result  # got end marker
            if md5sum and data[:2] == MD5_PARTITION_BEGIN[:2]:  # check only the magic number part
                if data[16:] == md5.digest():
                    continue  # the next iteration will check for the end marker
                else:
                    raise InputError(
                        "MD5 checksums don't match! (computed: 0x%s, parsed: 0x%s)"
                        % (md5.hexdigest(), binascii.hexlify(data[16:]))
                    )
            else:
                md5.update(data)
            result.append(PartitionDefinition.from_binary(data))
        raise InputError('Partition table is missing an end-of-table marker')

    def to_binary(self, md5sum=True):
        result = b''.join(e.to_binary() for e in self)
        if md5sum:
            result += MD5_PARTITION_BEGIN + hashlib.md5(result).digest()
        if len(result) >= MAX_PARTITION_LENGTH:
            raise InputError('Binary partition table length (%d) longer than max' % len(result))
        result += b'\xff' * (MAX_PARTITION_LENGTH - len(result))  # pad the sector, for signing
        return result

    def to_csv(self, simple_formatting=False):
        rows = ['# ESP-IDF Partition Table', '# Name, Type, SubType, Offset, Size, Flags']
        rows += [x.to_csv(simple_formatting) for x in self]
        return '\n'.join(rows) + '\n'


class PartitionDefinition(object):
    MAGIC_BYTES = b'\xaa\x50'

    # dictionary maps flag name (as used in CSV flags list, property name)
    # to bit set in flags words in binary format
    FLAGS = {'encrypted': 0, 'readonly': 1}

    # add subtypes for the 16 OTA slot values ("ota_XX, etc.")
    for ota_slot in range(NUM_PARTITION_SUBTYPE_APP_OTA):
        SUBTYPES[TYPES['app']]['ota_%d' % ota_slot] = MIN_PARTITION_SUBTYPE_APP_OTA + ota_slot

    # add subtypes for the 2 TEE OTA slot values ("tee_XX, etc.")
    for tee_slot in range(NUM_PARTITION_SUBTYPE_APP_TEE):
        SUBTYPES[TYPES['app']]['tee_%d' % tee_slot] = MIN_PARTITION_SUBTYPE_APP_TEE + tee_slot

    def __init__(self):
        self.name = ''
        self.type = None
        self.subtype = None
        self.offset = None
        self.size = None
        self.encrypted = False
        self.readonly = False

    @classmethod
    def default_bootloader(cls, offset, size):
        """ Create a default bootloader partition definition """
        res = PartitionDefinition()
        res.name = 'bootloader'
        res.type = TYPES['bootloader']
        res.subtype = SUBTYPES[TYPES['bootloader']]['primary']
        res.offset = offset
        res.size = size
        return res

    @classmethod
    def default_partition_table(cls, offset, size):
        """ Create a default partition table definition """
        res = PartitionDefinition()
        res.name = 'partition_table'
        res.type = TYPES['partition_table']
        res.subtype = SUBTYPES[TYPES['partition_table']]['primary']
        res.offset = offset
        res.size = size
        return res


    @classmethod
    def from_csv(cls, line, line_no, partition_table_offset: int = PARTITION_TABLE_OFFSET, primary_bootloader_offset: Optional[int] = None, recovery_bootloader_offset: Optional[int] = None):
        """Parse a line from the CSV"""
        line_w_defaults = line + ',,,,'  # lazy way to support default fields
        fields = [f.strip() for f in line_w_defaults.split(',')]

        res = PartitionDefinition()
        res.line_no = line_no
        res.name = fields[0]
        res.type = res.parse_type(fields[1])
        res.subtype = res.parse_subtype(fields[2])
        res.offset = res.parse_address(fields[3], res.type, res.subtype, partition_table_offset, primary_bootloader_offset, recovery_bootloader_offset)
        res.size = res.parse_size(fields[4], res.type, partition_table_offset, primary_bootloader_offset)
        if res.size is None:
            raise InputError("Size field can't be empty")

        flags = fields[5].split(':')
        for flag in flags:
            if flag in cls.FLAGS:
                setattr(res, flag, True)
            elif len(flag) > 0:
                raise InputError("CSV flag column contains unknown flag '%s'" % (flag))

        return res

    def __eq__(self, other):
        return (
            self.name == other.name
            and self.type == other.type
            and self.subtype == other.subtype
            and self.offset == other.offset
            and self.size == other.size
        )

    def __repr__(self):
        def maybe_hex(x):
            return '0x%x' % x if x is not None else 'None'

        return "PartitionDefinition('%s', 0x%x, 0x%x, %s, %s)" % (
            self.name,
            self.type,
            self.subtype or 0,
            maybe_hex(self.offset),
            maybe_hex(self.size),
        )

    def __str__(self):
        return "Part '%s' %d/%d @ 0x%x size 0x%x" % (
            self.name,
            self.type,
            self.subtype,
            self.offset or -1,
            self.size or -1,
        )


    def __cmp__(self, other):
        return self.offset - other.offset

    def __lt__(self, other):
        return self.offset < other.offset

    def __gt__(self, other):
        return self.offset > other.offset

    def __le__(self, other):
        return self.offset <= other.offset

    def __ge__(self, other):
        return self.offset >= other.offset

    def parse_type(self, strval):
        if strval == '':
            raise InputError("Field 'type' can't be left empty.")
        return parse_int(strval, TYPES)

    def parse_subtype(self, strval):
        if strval == '':
            if self.type == TYPES['app']:
                raise InputError('App partition cannot have an empty subtype')
            return SUBTYPES[DATA_TYPE]['undefined']
        return parse_int(strval, SUBTYPES.get(self.type, {}))

    def parse_size(self, strval, ptype, partition_table_offset: Optional[int] = None, primary_bootloader_offset: Optional[int] = None):
        if ptype == BOOTLOADER_TYPE:
            if partition_table_offset is None:
                raise InputError('Partition table offset is not provided')
            if primary_bootloader_offset is None:
                raise InputError('Primary bootloader offset is not provided')
            return partition_table_offset - primary_bootloader_offset
        if ptype == PARTITION_TABLE_TYPE:
            return PARTITION_TABLE_SIZE
        if strval == '':
            return None  # PartitionTable will fill in default
        return parse_int(strval)

    def parse_address(self, strval, ptype, psubtype, partition_table_offset: Optional[int] = None, primary_bootloader_offset: Optional[int] = None, recovery_bootloader_offset: Optional[int] = None):
        if ptype == BOOTLOADER_TYPE:
            if psubtype == SUBTYPES[ptype]['primary']:
                if primary_bootloader_offset is None:
                    raise InputError('Primary bootloader offset is not provided')
                return primary_bootloader_offset
            if psubtype == SUBTYPES[ptype]['recovery']:
                if recovery_bootloader_offset is None:
                    raise InputError('Recovery bootloader offset is not provided')
                return recovery_bootloader_offset
        if ptype == PARTITION_TABLE_TYPE and psubtype == SUBTYPES[ptype]['primary']:
            if partition_table_offset is None:
                raise InputError('Partition table offset is not provided')
            return partition_table_offset
        if strval == '':
            return None  # PartitionTable will fill in default
        return parse_int(strval)

    def verify(self, secure: Optional[str] = SECURE_NONE):
        if self.type is None:
            raise ValidationError(self, 'Type field is not set')
        if self.subtype is None:
            raise ValidationError(self, 'Subtype field is not set')
        if self.offset is None:
            raise ValidationError(self, 'Offset field is not set')
        if self.size is None:
            raise ValidationError(self, 'Size field is not set')
        offset_align = get_alignment_offset_for_type(self.type)
        if self.offset % offset_align:
            raise ValidationError(self, 'Offset 0x%x is not aligned to 0x%x' % (self.offset, offset_align))
        if self.type == APP_TYPE:
            size_align = get_alignment_size_for_type(self.type, secure)
            if self.size % size_align:
                raise ValidationError(self, 'Size 0x%x is not aligned to 0x%x' % (self.size, size_align))

        all_subtype_names = []
        for names in (t.keys() for t in SUBTYPES.values()):
            all_subtype_names += names

        always_rw_data_subtypes = [SUBTYPES[DATA_TYPE]['ota'], SUBTYPES[DATA_TYPE]['coredump']]
        if self.type == TYPES['data'] and self.subtype in always_rw_data_subtypes and self.readonly is True:
            raise ValidationError(
                self,
                "'%s' partition of type %s and subtype %s is always read-write and cannot be read-only"
                % (self.name, self.type, self.subtype),
            )

        if self.type == TYPES['data'] and self.subtype == SUBTYPES[DATA_TYPE]['nvs']:
            if self.size < NVS_RW_MIN_PARTITION_SIZE and self.readonly is False:
                raise ValidationError(
                    self,
                    """'%s' partition of type %s and subtype %s of this size (0x%x) must be flagged as 'readonly' \
(the size of read/write NVS has to be at least 0x%x)"""
                    % (self.name, self.type, self.subtype, self.size, NVS_RW_MIN_PARTITION_SIZE),
                )

    STRUCT_FORMAT = b'<2sBBLL16sL'

    @classmethod
    def from_binary(cls, b):
        if len(b) != 32:
            raise InputError('Partition definition length must be exactly 32 bytes. Got %d bytes.' % len(b))
        res = cls()
        (magic, res.type, res.subtype, res.offset, res.size, res.name, flags) = struct.unpack(cls.STRUCT_FORMAT, b)
        if b'\x00' in res.name:  # strip null byte padding from name string
            res.name = res.name[: res.name.index(b'\x00')]
        res.name = res.name.decode()
        if magic != cls.MAGIC_BYTES:
            raise InputError('Invalid magic bytes (%r) for partition definition' % magic)
        for flag, bit in cls.FLAGS.items():
            if flags & (1 << bit):
                setattr(res, flag, True)
                flags &= ~(1 << bit)
        return res

    def get_flags_list(self):
        return [flag for flag in self.FLAGS.keys() if getattr(self, flag)]

    def to_binary(self):
        flags = sum((1 << self.FLAGS[flag]) for flag in self.get_flags_list())
        return struct.pack(
            self.STRUCT_FORMAT,
            self.MAGIC_BYTES,
            self.type,
            self.subtype,
            self.offset,
            self.size,
            self.name.encode(),
            flags,
        )

    def to_csv(self, simple_formatting=False):
        def addr_format(a, include_sizes):
            if not simple_formatting and include_sizes:
                for val, suffix in [(0x100000, 'M'), (0x400, 'K')]:
                    if a % val == 0:
                        return '%d%s' % (a // val, suffix)
            return '0x%x' % a

        def lookup_keyword(t, keywords):
            for k, v in keywords.items():
                if simple_formatting is False and t == v:
                    return k
            return '%d' % t

        def generate_text_flags():
            """colon-delimited list of flags"""
            return ':'.join(self.get_flags_list())

        return ','.join(
            [
                self.name,
                lookup_keyword(self.type, TYPES),
                lookup_keyword(self.subtype, SUBTYPES.get(self.type, {})),
                addr_format(self.offset, False),
                addr_format(self.size, True),
                generate_text_flags(),
            ]
        )


def parse_int(v, keywords={}):
    """Generic parser for integer fields - int(x,0) with provision for
    k/m/K/M suffixes and 'keyword' value lookup.
    """
    try:
        for letter, multiplier in [('k', 1024), ('m', 1024 * 1024)]:
            if v.lower().endswith(letter):
                return parse_int(v[:-1], keywords) * multiplier
        return int(v, 0)
    except ValueError:
        if len(keywords) == 0:
            raise InputError('Invalid field value %s' % v)
        try:
            return keywords[v.lower()]
        except KeyError:
            raise InputError("Value '%s' is not valid. Known keywords: %s" % (v, ', '.join(keywords)))


class InputError(RuntimeError):
    def __init__(self, e):
        super(InputError, self).__init__(e)

class ValidationError(InputError):
    def __init__(self, partition, message):
        super(ValidationError, self).__init__(
            'Partition %s invalid: %s' % (partition.name, message))