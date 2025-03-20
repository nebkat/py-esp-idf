from __future__ import annotations

import collections
import struct
from dataclasses import dataclass
from enum import IntEnum
from functools import reduce
from hashlib import sha256
from typing import ClassVar, NamedTuple, List

from esp_idf_defs.app_description import AppDescription


@dataclass
class ImageMetadata:
    """ESP-IDF firmware image metadata (`esp_image_metadata_t`)"""

    # `ESP_ROM_CHECKSUM_INITIAL` / `ESP_CHECKSUM_MAGIC`
    CHECKSUM_MAGIC: ClassVar[int] = 0xEF

    header: ImageHeader
    segments: List[ImageSegment]
    digest: bytes
    app_description: AppDescription | None

    @classmethod
    def from_bytes(cls, buffer: bytes, app_required: bool = False) -> ImageMetadata:
        header = ImageHeader.from_bytes(buffer[0:ImageHeader.SIZE])
        offset = ImageHeader.SIZE
        segments: List[ImageSegment] = []
        checksum = ImageMetadata.CHECKSUM_MAGIC
        app_description: AppDescription | None = None
        for i in range(header.segment_count):
            address, length = struct.unpack_from('<II', buffer, offset)
            offset += 8
            segment = ImageSegment(offset, length, address)

            data = buffer[offset:offset+length]
            checksum = reduce(lambda a, b: a ^ b & 0xFF, data, checksum)

            if i == 0:
                app_description = AppDescription.from_bytes(data) if app_required else AppDescription.from_bytes_or_none(data)

            offset += length
            segments.append(segment)

        # Add a byte for the checksum
        offset += 1

        # Pad to the next full 16 byte block
        offset = (offset + 15) & ~0xF

        # Checksum (simple)
        expected_checksum = struct.unpack_from('<B', buffer, offset - 1)[0]
        if checksum != expected_checksum:
            raise ValueError(f"Checksum mismatch: expected {expected_checksum:#02x}, got {checksum:#02x}")

        # Hash (SHA-256)
        digest = sha256(buffer[:offset]).digest()
        if header.hash_appended:
            expected_hash = buffer[offset:offset+32]
            if digest != expected_hash:
                raise ValueError(f"SHA-256 hash mismatch: expected {expected_hash.hex()}, got {digest.hex()}")

        return cls(
            header=header,
            segments=segments,
            digest=digest,
            app_description=app_description
        )



@dataclass
class ImageHeader:
    # `ESP_IMAGE_HEADER_MAGIC`
    MAGIC: ClassVar[int] = 0xE9

    # `ESP_IMAGE_HEADER_MAGIC`
    MAX_SEGMENTS: ClassVar[int] = 16

    # `sizeof(esp_image_header_t)`
    SIZE: ClassVar[int] = 24

    # `WP_PIN_DISABLED`
    WP_PIN_DISABLED: ClassVar[int] = 0xEE

    @classmethod
    def from_bytes(cls, buffer: bytes) -> ImageHeader:
        if len(buffer) < cls.SIZE:
            raise ValueError(f"Invalid image header, expected >= 24 bytes, got {len(buffer)}")

        magic = struct.unpack_from('<B', buffer, 0)[0]
        if magic != cls.MAGIC:
            raise ValueError(f"Invalid image header, magic not found: expected {cls.MAGIC:#02x}, got {magic:#02x}")

        segment_count = struct.unpack_from('<B', buffer, 1)[0]
        if segment_count == 0 or segment_count > cls.MAX_SEGMENTS:
            raise ValueError(
                f"Invalid image header, bad segment count: {segment_count}: "
                f"expected 1..{cls.MAX_SEGMENTS}")

        wp_pin = struct.unpack_from('<B', buffer, 8)[0]

        return cls(
            segment_count=segment_count,
            spi_mode = ImageSpiMode(struct.unpack_from('<B', buffer, 2)[0]),
            spi_frequency = ImageSpiFrequency(struct.unpack_from('<B', buffer, 3)[0] & 0xF),
            spi_size = ImageFlashSize(struct.unpack_from('<B', buffer, 3)[0] >> 4),
            entry_address = struct.unpack_from('<I', buffer, 4)[0],
            wp_pin = wp_pin if wp_pin != cls.WP_PIN_DISABLED else None,
            spi_pin_drv = struct.unpack_from('<BBB', buffer, 9),
            chip_id = ChipId(struct.unpack_from('<H', buffer, 12)[0]),
            min_chip_rev = struct.unpack_from('<B', buffer, 14)[0],
            min_chip_rev_full = struct.unpack_from('<H', buffer, 15)[0],
            max_chip_rev_full = struct.unpack_from('<H', buffer, 11)[0],
            hash_appended = bool(struct.unpack_from('<B', buffer, 23)[0] == 1)
        )

    segment_count: int
    spi_mode: ImageSpiMode | None
    spi_frequency: ImageSpiFrequency | None
    spi_size: ImageFlashSize | None
    entry_address: int
    wp_pin: int | None
    spi_pin_drv: (int, int, int)
    chip_id: ChipId | None
    min_chip_rev: int
    min_chip_rev_full: int
    max_chip_rev_full: int
    hash_appended: bool

ImageSegment = NamedTuple("ImageSegment", [
    ("offset", int),
    ("length", int),
    ("address", int)
])

# `esp_image_spi_mode_t`
class ImageSpiMode(IntEnum):
    QIO = 0x0
    QOUT = 0x1
    DIO = 0x2
    DOUT = 0x3
    FAST_READ = 0x4
    SLOW_READ = 0x5

# `esp_image_spi_freq_t`
class ImageSpiFrequency(IntEnum):
    DIV1 = 0xF
    DIV2 = 0x0
    DIV3 = 0x1
    DIV4 = 0x2

# `esp_chip_id_t`
class ChipId(IntEnum):
    ESP32 = 0x0000
    ESP32S2 = 0x0002
    ESP32C3 = 0x0005
    ESP32S3 = 0x0009
    ESP32C2 = 0x000C
    ESP32C6 = 0x000D
    ESP32H2 = 0x0010
    ESP32P4 = 0x0012
    ESP32C5 = 0x0017

# `esp_image_flash_size_t`
class ImageFlashSize(IntEnum):
    MB1 = 0x0
    MB2 = 0x1
    MB4 = 0x2
    MB8 = 0x3
    MB16 = 0x4
    MB32 = 0x5
    MB64 = 0x6
    MB128 = 0x7