from scapy.layers.tls.crypto.suites import TLS_AES_128_GCM_SHA256
from scapy.layers.tls.handshake import TLSServerHello, TLS13ServerHello
from scapy.layers.tls.record import TLS, TLSApplicationData

import utils
from time_series.flow_clumps import Clump, FlowClumps


class Processor:
    def __init__(self, flow):
        self.flow = flow

        self._segment_size = 20
        self._cipher = None

    def _clumps(self):
        current_clump = None

        for packet, direction in self.flow.packets:
            if TLS not in packet:
                continue

            if TLSApplicationData not in packet:
                if self._cipher is None:
                    if TLSServerHello in packet:
                        self._cipher = packet[TLSServerHello].cipher
                    elif TLS13ServerHello in packet:
                        self._cipher = packet[TLS13ServerHello].cipher
                continue

            if self._cipher is None:
                break

            if self._cipher == TLS_AES_128_GCM_SHA256.val and len(packet[TLSApplicationData]) < 40:
                # PING frame (len = 34) or other useless frames
                continue

            if current_clump is None:
                current_clump = Clump(direction=direction)

            if not current_clump.accepts(packet, direction):
                yield current_clump
                current_clump = Clump(direction=direction)

            current_clump.add_packet(packet)

        if current_clump is not None:
            yield current_clump

    def create_flow_clumps(self):
        return FlowClumps(flow=self.flow, clumps=self._clumps())
