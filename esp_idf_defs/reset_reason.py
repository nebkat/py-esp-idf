from __future__ import annotations

from enum import IntEnum


class ResetReason(IntEnum):
    """`esp_reset_reason_t`, as `esp_reset_reason()` returns it."""
    UNKNOWN    = 0
    POWERON    = 1
    EXT        = 2
    SW         = 3
    PANIC      = 4
    INT_WDT    = 5
    TASK_WDT   = 6
    WDT        = 7
    DEEPSLEEP  = 8
    BROWNOUT   = 9
    SDIO       = 10
    USB        = 11
    JTAG       = 12
    EFUSE      = 13
    PWR_GLITCH = 14
    CPU_LOCKUP = 15

    @classmethod
    def _missing_(cls, value: object) -> ResetReason:
        return cls.UNKNOWN

    @property
    def is_watchdog(self) -> bool:
        return self in (ResetReason.INT_WDT, ResetReason.TASK_WDT, ResetReason.WDT)
