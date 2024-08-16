from . import TT02HackApplet
from ... import GlasgowAppletTestCase, synthesis_test


class TT02HackAppletTestCase(GlasgowAppletTestCase, applet=TT02HackApplet):
    @synthesis_test
    def test_build(self) -> None:
        self.assertBuilds()
