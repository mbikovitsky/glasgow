from . import TT02LFSRApplet
from ... import GlasgowAppletTestCase, synthesis_test


class TT02LFSRAppletTestCase(GlasgowAppletTestCase, applet=TT02LFSRApplet):
    @synthesis_test
    def test_build(self) -> None:
        self.assertBuilds()
