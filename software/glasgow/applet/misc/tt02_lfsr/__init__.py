import logging
from argparse import ArgumentParser, Namespace

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
from ....platform.generic import GlasgowGenericPlatform
from ....target.hardware import GlasgowHardwareTarget
from ... import GlasgowApplet


class TT02LFSRApplet(GlasgowApplet):
    logger = logging.getLogger(__name__)
    help = "operate the LFSR in TT02 design #33"

    ASIC_CLOCK_HZ = 625
    LFSR_WIDTH = 5

    @classmethod
    def add_build_arguments(
        cls, parser: ArgumentParser, access: AccessArguments
    ) -> None:
        super().add_build_arguments(parser, access)

        access.add_pin_argument(parser, "clk", default=True)
        access.add_pin_argument(parser, "reset_lfsr", default=True)
        access.add_pin_argument(parser, "reset_taps", default=True)
        access.add_pin_set_argument(parser, "data", cls.LFSR_WIDTH, default=True)

    def build(self, target: GlasgowHardwareTarget, args: Namespace) -> None:
        clk_cycles = self.derive_clock(
            input_hz=target.sys_clk_freq,
            output_hz=self.ASIC_CLOCK_HZ,
            min_cyc=2,
            max_deviation_ppm=50000,
        )

        self._mux_interface = iface = target.multiplexer.claim_interface(self, args)
        assert isinstance(iface, AccessMultiplexerInterface)

        pads = iface.get_deprecated_pads(
            args,
            pins=("clk", "reset_lfsr", "reset_taps"),
            pin_sets=("data",),
        )

        taps, self._taps_addr = target.registers.add_rw(self.LFSR_WIDTH)
        initial_state, self._initial_state_addr = target.registers.add_rw(
            self.LFSR_WIDTH
        )
        go, self._go_addr = target.registers.add_rw(1)
        done, self._done_addr = target.registers.add_ro(1)

        iface.add_subtarget(
            TT02LFSRSubtarget(
                asic_clk_cycles=clk_cycles,
                pads=pads,
                taps_reg=taps,
                initial_state_reg=initial_state,
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

        parser.add_argument(
            "--taps",
            type=lambda x: int(x, 0),
            default=0x12,
            help="LFSR taps",
        )
        parser.add_argument(
            "--initial",
            type=lambda x: int(x, 0),
            default=0x12,
            help="LFSR initial state",
        )

    async def interact(
        self,
        device: GlasgowHardwareDevice,
        args: Namespace,
        iface: AccessDemultiplexerInterface,
    ) -> None:
        taps = args.taps
        initial = args.initial

        await device.write_register(self._taps_addr, taps, width=self.LFSR_WIDTH)
        await device.write_register(
            self._initial_state_addr, initial, width=self.LFSR_WIDTH
        )
        await device.write_register(self._go_addr, 1)
        while not await device.read_register(self._done_addr):
            pass
        await device.write_register(self._go_addr, 0)


class TT02LFSRSubtarget(Elaboratable):
    def __init__(
        self,
        *,
        asic_clk_cycles: int,
        pads: _DeprecatedPads,
        taps_reg: Signal,
        initial_state_reg: Signal,
        go_reg: Signal,
        done_reg: Signal,
    ) -> None:
        self._asic_clk_cycles = asic_clk_cycles
        self._pads = pads
        self._taps_reg = taps_reg
        self._initial_state_reg = initial_state_reg
        self._go_reg = go_reg
        self._done_reg = done_reg

        assert len(pads.reset_taps_t.o) == len(pads.reset_lfsr_t.o) == 1
        assert len(pads.clk_t.o) == 1
        assert len(pads.data_t.o) == len(initial_state_reg) == len(taps_reg)
        assert len(go_reg) == len(done_reg) == 1

    def elaborate(self, platform: GlasgowGenericPlatform) -> Module:
        m = Module()

        m.submodules.asic_clk_gen = asic_clk_gen = ClockGen(self._asic_clk_cycles)

        # Output the ASIC clock to the specified pin
        m.d.comb += [
            self._pads.clk_t.oe.eq(1),
            self._pads.clk_t.o.eq(asic_clk_gen.clk),
        ]

        reset_lfsr = Signal()
        reset_taps = Signal()
        data = Signal(self._pads.data_t.o.shape())

        m.d.comb += [
            self._pads.reset_lfsr_t.oe.eq(1),
            self._pads.reset_lfsr_t.o.eq(reset_lfsr),
        ]
        m.d.comb += [
            self._pads.reset_taps_t.oe.eq(1),
            self._pads.reset_taps_t.o.eq(reset_taps),
        ]
        m.d.comb += [
            self._pads.data_t.oe.eq(1),
            self._pads.data_t.o.eq(data),
        ]

        with m.FSM():
            with m.State("Idle"):
                with m.If(self._go_reg):
                    with m.If(asic_clk_gen.stb_f):
                        m.d.sync += data.eq(self._taps_reg)
                        m.d.sync += reset_taps.eq(1)
                        m.d.sync += reset_lfsr.eq(0)
                        m.next = "Set initial"

            with m.State("Set initial"):
                with m.If(asic_clk_gen.stb_f):
                    m.d.sync += data.eq(self._initial_state_reg)
                    m.d.sync += reset_taps.eq(0)
                    m.d.sync += reset_lfsr.eq(1)
                    m.next = "Run"

            with m.State("Run"):
                with m.If(asic_clk_gen.stb_f):
                    m.d.sync += reset_taps.eq(0)
                    m.d.sync += reset_lfsr.eq(0)
                    m.d.sync += self._done_reg.eq(1)
                    m.next = "Wait done"

            with m.State("Wait done"):
                with m.If(~self._go_reg):
                    m.d.sync += self._done_reg.eq(0)
                    m.next = "Idle"

        return m
