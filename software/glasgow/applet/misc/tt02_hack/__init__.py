import ctypes
import logging
import operator
from argparse import ArgumentParser, Namespace
from enum import IntEnum, IntFlag
from functools import reduce
from typing import Sequence

from amaranth import Elaboratable, Module, Signal

from ....access import (
    AccessArguments,
    AccessDemultiplexerInterface,
    AccessMultiplexerInterface,
    _DeprecatedPads,
)
from ....device.hardware import GlasgowHardwareDevice
from ....device.simulation import GlasgowSimulationDevice
from ....gateware.clockgen import ClockGen
from ....gateware.uart import UART
from ....platform.generic import GlasgowGenericPlatform
from ....target.hardware import GlasgowHardwareTarget
from ... import GlasgowApplet


SEVEN_SEGMENT_ENCODER = {
    0: 0b0111111,
    1: 0b0000110,
    2: 0b1011011,
    3: 0b1001111,
    4: 0b1100110,
    5: 0b1101101,
    6: 0b1111101,
    7: 0b0000111,
    8: 0b1111111,
    9: 0b1101111,
    10: 0b1110111,
    11: 0b1111100,
    12: 0b0111001,
    13: 0b1011110,
    14: 0b1111001,
    15: 0b1110001,
}


class AInstruction(ctypes.Union):
    class _Bits(ctypes.LittleEndianStructure):
        _fields_ = (
            ("address", ctypes.c_uint16, 15),
            ("reserved0_0", ctypes.c_uint16, 1),
        )

    _anonymous_ = ("u",)
    _fields_ = (("u", _Bits), ("full", ctypes.c_uint16))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reserved0_0 = 0b0

    def __int__(self) -> int:
        return self.full


class CInstruction(ctypes.Union):
    class _Bits(ctypes.LittleEndianStructure):
        _fields_ = (
            ("jump", ctypes.c_uint16, 3),
            ("dest", ctypes.c_uint16, 3),
            ("comp", ctypes.c_uint16, 6),
            ("a", ctypes.c_uint16, 1),
            ("extended", ctypes.c_uint16, 2),
            ("reserved0_1", ctypes.c_uint16, 1),
        )

    _anonymous_ = ("u",)
    _fields_ = (("u", _Bits), ("full", ctypes.c_uint16))

    def __init__(self, *args, extended=0b11, **kwargs):
        super().__init__(*args, **kwargs)
        self.extended = extended
        self.reserved0_1 = 0b1

    def __int__(self) -> int:
        return self.full


class JumpSpec(IntEnum):
    NONE = 0b000
    JGT = 0b001
    JEQ = 0b010
    JGE = 0b011
    JLT = 0b100
    JNE = 0b101
    JLE = 0b110
    JMP = 0b111


class DestSpec(IntFlag):
    NONE = 0b000
    A = 0b100
    D = 0b010
    M = 0b001


class TT02HackApplet(GlasgowApplet):
    logger = logging.getLogger(__name__)
    help = "operate the Hack CPU in TT02 design #33"

    ASIC_CLOCK_HZ = 625 * 3
    ROM_WORDS = 4
    UART_BAUD = ASIC_CLOCK_HZ / 8

    @classmethod
    def add_build_arguments(
        cls, parser: ArgumentParser, access: AccessArguments
    ) -> None:
        super().add_build_arguments(parser, access)

        access.add_pin_argument(parser, "clk", default=True)
        access.add_pin_set_argument(parser, "cpu_mode", 2, default=True)
        access.add_pin_argument(parser, "cpu_reset", default=True)
        access.add_pin_argument(parser, "mem_reset", default=True)
        access.add_pin_argument(parser, "tx", default=True)
        access.add_pin_argument(parser, "uart_reset", default=True)

    def build(self, target: GlasgowHardwareTarget, args: Namespace) -> None:
        clk_cycles = self.derive_clock(
            input_hz=target.sys_clk_freq,
            output_hz=self.ASIC_CLOCK_HZ,
            min_cyc=2,
            max_deviation_ppm=50000,
        )

        # Copied from the UART applet
        uart_cycles = (
            self.derive_clock(
                input_hz=target.sys_clk_freq,
                output_hz=self.UART_BAUD,
                min_cyc=2,
                max_deviation_ppm=50000,
            )
            - 1
        )

        self._mux_interface = iface = target.multiplexer.claim_interface(self, args)
        assert isinstance(iface, AccessMultiplexerInterface)

        pads = iface.get_deprecated_pads(
            args,
            pins=("clk", "cpu_reset", "mem_reset", "uart_reset", "tx"),
            pin_sets=("cpu_mode",),
        )

        program, self._program_addr = target.registers.add_rw(self.ROM_WORDS * 16)
        run_cycles, self._run_cycles_addr = target.registers.add_rw(32)
        go, self._go_addr = target.registers.add_rw(1)
        done, self._done_addr = target.registers.add_ro(1)

        iface.add_subtarget(
            TT02HackSubtarget(
                asic_clk_cycles=clk_cycles,
                uart_cycles=uart_cycles,
                pads=pads,
                program_reg=program,
                run_cycles_reg=run_cycles,
                go_reg=go,
                done_reg=done,
            )
        )

    async def run(
        self,
        device: GlasgowHardwareDevice | GlasgowSimulationDevice,
        args: Namespace,
    ) -> AccessDemultiplexerInterface:
        return await device.demultiplexer.claim_interface(
            self, self._mux_interface, args
        )

    @classmethod
    def add_interact_arguments(cls, parser: ArgumentParser) -> None:
        super().add_interact_arguments(parser)

        operations = parser.add_subparsers(dest="operation", required=True)

        show_num = operations.add_parser(
            "show_num",
            help="Show a number on the 7-segment display",
        )
        show_num.add_argument(
            "number",
            type=lambda x: int(x, 0),
            help="Number to display",
        )
        show_num.add_argument(
            "-H",
            "--hex",
            action="store_true",
            help="Display in base 16",
        )

        lfsr = operations.add_parser("lfsr", help="Run a 15-bit LFSR")
        lfsr.add_argument(
            "--taps",
            type=lambda x: int(x, 0),
            default=0x8E,
            help="LFSR taps",
        )
        lfsr.add_argument(
            "--initial",
            type=lambda x: int(x, 0),
            default=0x8E,
            help="LFSR initial state",
        )
        lfsr.add_argument(
            "--iterations",
            type=lambda x: int(x, 0),
            default=0xFF,
            help="LFSR iterations to run",
        )

    async def interact(
        self,
        device: GlasgowHardwareDevice,
        args: Namespace,
        iface: AccessDemultiplexerInterface,
    ) -> None:
        if args.operation == "show_num":
            assert args.number >= 0
            if args.hex:
                digits = [int(d, 16) for d in hex(args.number)[2:]]
            else:
                digits = [int(d, 10) for d in str(args.number)]

            version = 0
            for digit in digits:
                program = [
                    AInstruction(address=SEVEN_SEGMENT_ENCODER[digit]),  # @value
                    CInstruction(dest=DestSpec.M, a=0, comp=0b110000),  # M=A
                ]
                version = await self._run_program_trap(device, program, version)
                # Delay because of faster clock
                version = await self._run_program_trap(device, program, version)

                program = [
                    CInstruction(dest=DestSpec.M, a=0, comp=0b101010),  # M=0
                ]
                version = await self._run_program_trap(device, program, version)

        elif args.operation == "lfsr":
            init_program = [
                AInstruction(address=args.initial),  # @initial
                CInstruction(dest=DestSpec.M | DestSpec.D, a=0, comp=0b110000),  # MD=A
            ]
            version = await self._run_program_trap(device, init_program, 0)

            lfsr_program = [
                # @1
                AInstruction(address=1),
                # D=D&A
                CInstruction(dest=DestSpec.D, a=0, comp=0b000000),
                # D=-D
                CInstruction(dest=DestSpec.D, a=0, comp=0b001111),
                # @0
                AInstruction(address=0),  # Padding
                # @taps
                AInstruction(address=args.taps),
                # D=D&A
                CInstruction(dest=DestSpec.D, a=0, comp=0b000000),
                # M=M>>
                CInstruction(dest=DestSpec.M, a=1, comp=0b000000, extended=0b01),
                # MD=D^M
                CInstruction(
                    dest=DestSpec.M | DestSpec.D,
                    a=1,
                    comp=0b000000,
                    extended=0b00,
                ),
            ]

            for iteration in range(args.iterations):
                self.logger.info("running LFSR iteration %d", iteration)

                for i in range(0, len(lfsr_program), 2):
                    version = await self._run_program_trap(
                        device,
                        lfsr_program[i : i + 2],
                        version,
                    )

    async def _run_program_trap(
        self,
        device: GlasgowHardwareDevice,
        program: Sequence[int | AInstruction | CInstruction],
        version: int,
    ) -> int:
        if version:
            trap = [
                CInstruction(dest=DestSpec.A, a=0, comp=0b111010),  # A=-1
                CInstruction(jump=JumpSpec.JLT, a=0, comp=0b110000),  # A;JLT
            ]
        else:
            trap = [
                AInstruction(address=self.ROM_WORDS - 1),  # @END_OF_MEMORY
                CInstruction(jump=JumpSpec.JGT, a=0, comp=0b110000),  # A;JGT
            ]

        assert self.ROM_WORDS - len(program) >= len(trap)

        full_program = [
            *program,
            *([AInstruction(address=0)] * (self.ROM_WORDS - len(program) - len(trap))),
            *trap,
        ]

        await self._run_program(device, full_program, cycles=0)

        return ~version

    async def _run_program(
        self,
        device: GlasgowHardwareDevice,
        program: Sequence[int | AInstruction | CInstruction],
        *,
        cycles: int | None = None,
    ) -> None:
        assert len(program) <= self.ROM_WORDS
        assert all(0 <= int(instruction) < 2**16 for instruction in program)

        if cycles is None:
            cycles = len(program)
        assert cycles >= 0

        program_int = reduce(
            operator.or_,
            (int(instruction) << (i * 16) for i, instruction in enumerate(program)),
        )

        await device.write_register(
            self._program_addr,
            program_int,
            width=self.ROM_WORDS * 16,
        )
        await device.write_register(self._run_cycles_addr, cycles, width=32)
        await device.write_register(self._go_addr, 1)
        while not await device.read_register(self._done_addr):
            pass
        await device.write_register(self._go_addr, 0)


class TT02HackSubtarget(Elaboratable):
    def __init__(
        self,
        *,
        asic_clk_cycles: int,
        uart_cycles: int,
        pads: _DeprecatedPads,
        program_reg: Signal,
        run_cycles_reg: Signal,
        go_reg: Signal,
        done_reg: Signal,
    ) -> None:
        self._asic_clk_cycles = asic_clk_cycles
        self._uart_cycles = uart_cycles
        self._pads = pads
        self._program_reg = program_reg
        self._run_cycles_reg = run_cycles_reg
        self._go_reg = go_reg
        self._done_reg = done_reg

        assert len(pads.clk_t.o) == 1
        assert len(pads.cpu_mode_t.o) == 2
        assert (
            len(pads.cpu_reset_t.o)
            == len(pads.mem_reset_t.o)
            == len(pads.uart_reset_t.o)
            == 1
        )
        assert len(pads.tx_t.o) == 1
        assert len(go_reg) == len(done_reg) == 1

    def elaborate(self, platform: GlasgowGenericPlatform) -> Module:
        m = Module()

        m.submodules.asic_clk_gen = asic_clk_gen = ClockGen(self._asic_clk_cycles)

        # Output the ASIC clock to the specified pin
        m.d.comb += [
            self._pads.clk_t.oe.eq(1),
            self._pads.clk_t.o.eq(asic_clk_gen.clk),
        ]

        # Put the ASIC into CPU mode
        m.d.comb += [
            self._pads.cpu_mode_t.oe.eq(1),
            self._pads.cpu_mode_t.o.eq(0b11),
        ]

        # Reset everything on "boot"
        cpu_reset = Signal(init=1)
        mem_reset = Signal(init=1)
        uart_reset = Signal(init=1)
        m.d.comb += [
            self._pads.cpu_reset_t.oe.eq(1),
            self._pads.mem_reset_t.oe.eq(1),
            self._pads.uart_reset_t.oe.eq(1),
            self._pads.cpu_reset_t.o.eq(cpu_reset),
            self._pads.mem_reset_t.o.eq(mem_reset),
            self._pads.uart_reset_t.o.eq(uart_reset),
        ]

        m.submodules.uart = uart = UART(
            self._pads,
            bit_cyc=self._uart_cycles,
            data_bits=8,
            parity="none",
        )

        assert len(self._program_reg) % 8 == 0
        program_bytes = len(self._program_reg) // 8

        current_upload_byte = Signal(range(program_bytes))

        run_cycles = Signal.like(self._run_cycles_reg)

        with m.FSM():
            with m.State("Idle"):
                with m.If(self._go_reg):
                    with m.If(asic_clk_gen.stb_f):
                        m.d.sync += uart_reset.eq(0)
                        m.next = "Release UART reset"

            with m.State("Release UART reset"):
                # Wait until the ASIC gets the reset release
                with m.If(asic_clk_gen.stb_f):
                    m.d.sync += uart.tx_ack.eq(1)
                    m.next = "Upload"

            # Technically it's unnecessary to clear the PROM, since we always
            # overwrite the whole thing -- the program register has the same size.
            # But, this is what I did in pre-silicon, so let's keep it :)
            # with m.State("Clear PROM"):
            #     m.d.comb += uart.tx_data.eq(0)
            #     with m.If(uart.tx_rdy):
            #         m.d.sync += current_upload_byte.eq(current_upload_byte + 1)
            #         with m.If(current_upload_byte == program_bytes - 1):
            #             m.d.sync += current_upload_byte.eq(0)
            #             m.next = "Upload"

            with m.State("Upload"):
                m.d.comb += uart.tx_data.eq(
                    self._program_reg.word_select(current_upload_byte, 8)
                )
                with m.If(uart.tx_rdy):
                    m.d.sync += current_upload_byte.eq(current_upload_byte + 1)
                    with m.If(current_upload_byte == program_bytes - 1):
                        m.d.sync += current_upload_byte.eq(0)
                        m.d.sync += uart.tx_ack.eq(0)
                        m.next = "Wait upload done"

            with m.State("Wait upload done"):
                with m.If(uart.tx_rdy & asic_clk_gen.stb_f):
                    m.d.sync += [
                        uart_reset.eq(1),
                        cpu_reset.eq(0),
                        mem_reset.eq(0),
                    ]
                    with m.If(self._run_cycles_reg == 0):
                        m.next = "CPU done"
                    with m.Else():
                        m.next = "Run CPU"

            with m.State("Run CPU"):
                with m.If(asic_clk_gen.stb_f):
                    m.d.sync += run_cycles.eq(run_cycles + 1)
                    with m.If(run_cycles == self._run_cycles_reg):
                        m.d.sync += run_cycles.eq(0)
                        m.d.sync += cpu_reset.eq(1)
                        m.next = "CPU done"

            with m.State("CPU done"):
                m.d.sync += self._done_reg.eq(1)
                with m.If(~self._go_reg):
                    m.d.sync += self._done_reg.eq(0)
                    m.next = "Idle"

        return m
