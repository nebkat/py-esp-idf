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
    compiled: str | None = None

    @property
    def title(self):
        return f"{self.project_name} {self.version}"

    @classmethod
    def from_bytes(cls, buffer: bytes) -> AppDescription | None:
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
        compiled = f"{date} {time}" if date and time else None

        elf_sha256 = buffer[144:176]

        return cls(
            project_name=project_name,
            version=version,
            idf_version=idf_version,
            secure_version=secure_version,
            compiled=compiled,
            elf_sha256=elf_sha256
        )