#!/usr/bin/env python

from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

#internal imports
from Features import Features
from ContElements.Context.PacketDirection import PacketDirection
from ContElements.Context.PacketFlowKey import PacketFlowKey

class FlowList:
    """Creates a list of network flows.

    """
    def __init__(self, interface, packets) -> None:
        local_mac = get_if_hwaddr(interface)
        self.flows = {}

        for packet in packets:
            if packet.src == local_mac:
                if packet.dst == local_mac and PacketFlowKey.get_packet_flow_key(packet, PacketDirection.REVERSE):
                    direction = PacketDirection.REVERSE
                else:
                    direction = PacketDirection.FORWARD
            elif packet.dst == local_mac:
                direction = PacketDirection.REVERSE
            else:
                direction = PacketDirection.FORWARD

            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
            flow = self.flows.get(packet_flow_key)
            if flow is None:
                flow = Features(packet, direction, interface)
                self.flows[packet_flow_key] = flow

            flow.add_packet(packet, direction)

    def get_flows(self) -> list:
        return self.flows.values()