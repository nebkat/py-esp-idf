from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class AppDescription:
    # `ESP_APP_DESC_MAGIC_WORD`
    MAGIC: ClassVar[int] = 0xABCD5432

    # sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)
    FIRMWARE_BINARY_OFFSET: ClassVar[int] = 0x20

    # `sizeof(esp_app_desc_t)`
    SIZE: ClassVar[int] = 256

    project_name: str
    version: str
    idf_version: str
    secure_version: int
    elf_sha256: bytes
    time: str | None = None
    date: str | None = None

    @property
    def title(self) -> str:
        return f"{self.project_name} {self.version}"

    @property
    def compiled(self) -> str | None:
        if self.date and self.time:
            return f"{self.date} {self.time}"
        return None

    @classmethod
    def from_bytes(cls, buffer: bytes) -> AppDescription:
        if len(buffer) < cls.SIZE:
            raise ValueError(f"Invalid app description, expected >= 256 bytes, got {len(buffer)}")

        if struct.unpack_from('<I', buffer, 0)[0] != cls.MAGIC:
            raise ValueError("Invalid firmware file, magic not found")

        def decode_string(start, length):
            return buffer[start:start + length].split(b'\x00', 1)[0].decode('utf-8')

        project_name = decode_string(48, 32)
        version = decode_string(16, 32)
        idf_version = decode_string(112, 32)
        secure_version = struct.unpack_from('<I', buffer, 4)[0]

        time = decode_string(80, 16)
        date = decode_string(96, 16)

        elf_sha256 = buffer[144:176]

        return cls(
            project_name=project_name,
            version=version,
            idf_version=idf_version,
            secure_version=secure_version,
            time=time,
            date=date,
            elf_sha256=elf_sha256
        )

    @classmethod
    def from_bytes_or_none(cls, buffer: bytes) -> AppDescription | None:
        try:
            return cls.from_bytes(buffer)
        except ValueError:
            return None

    def to_bytes(self) -> bytes:
        def encode_field(value: str | None, length: int) -> bytes:
            """Helper function to encode a string or None into a fixed-length byte array."""
            if value:
                return value.encode('utf-8')[:length].ljust(length, b'\x00')
            return b'\x00' * length

        buffer = bytearray(self.SIZE)
        struct.pack_into('<I', buffer, 0, self.MAGIC)
        struct.pack_into('<I', buffer, 4, self.secure_version)
        buffer[48:80] = encode_field(self.project_name, 32)
        buffer[16:48] = encode_field(self.version, 32)
        buffer[112:144] = encode_field(self.idf_version, 32)
        buffer[80:96] = encode_field(self.time, 16)
        buffer[96:112] = encode_field(self.date, 16)
        buffer[144:176] = self.elf_sha256
        return bytes(buffer)