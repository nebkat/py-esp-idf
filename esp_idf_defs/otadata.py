from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from typing import ClassVar, Tuple, Literal


@dataclass
class OtaDataSelectEntry:
    # `sizeof(esp_ota_select_entry_t)`
    SIZE: ClassVar[int] = 32

    seq: int
    ota_state: int = 0

    @classmethod
    def from_ota_slot(cls, ota_slot: int) -> OtaDataSelectEntry:
        return cls(ota_slot + 1)

    @classmethod
    def from_bytes(cls, buffer: bytes) -> OtaDataSelectEntry | None:
        seq, ota_state, crc = struct.unpack_from('<I20xII', buffer, 0)
        expected_crc = crc = binascii.crc32(struct.pack('I', seq), 0xFFFFFFFF)
        if crc != expected_crc or seq == 0xFFFFFFFF:
            return None
        else:
            return OtaDataSelectEntry(seq, ota_state)

    def to_bytes(self) -> bytes:
        return struct.pack(
            '<I20sII',
            self.seq,
             b'\xFF'*20,
             self.ota_state,
             binascii.crc32(struct.pack('I', self.seq), 0xFFFFFFFF)
        )

    @classmethod
    def select(cls, a: OtaDataSelectEntry | None, b: OtaDataSelectEntry | None) -> Tuple[OtaDataSelectEntry, Literal['a', 'b']] | Tuple[None, None]:
        if not a and not b:
            return None, None
        if not b:
            return a, 'a'
        if not a:
            return b, 'b'

        if a.seq > b.seq:
            return a, 'a'
        else:
            return b, 'b'

    def ota_slot(self, ota_app_count):
        return (self.seq - 1) % ota_app_count

    def incremented(self, ota_slot, ota_count) -> OtaDataSelectEntry:
        ota_slot_diff = (((ota_slot - self.ota_slot(ota_count)) + ota_count - 1) % ota_count) + 1
        return OtaDataSelectEntry(self.seq + ota_slot_diff)