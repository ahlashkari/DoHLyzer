#!/usr/bin/env python

import os
import sys

from datetime import timedelta
from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

#internal imports
from Flow import Flow
from ContElements.Context.PacketDirection import PacketDirection
from ContElements.Context.PacketFlowKey import PacketFlowKey

sys.path.append(os.path.realpath('..'))
from ContFreeElements import PacketTime

class FlowList:
    """Creates a list of network flows.

    """
    def __init__(self, interface, packets) -> None:
        # local_mac = get_if_hwaddr(interface)
        self.flows = {}
        for packet in packets:

            direction = PacketDirection.FORWARD

            #Creates a variable to check
            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)

            #checkes if the variable is a key
            #if it is, there will be something returned
            flow = self.flows.get(packet_flow_key)

            #if the there isn't a key by that variable name
            #then it returns None
            #and the program proceeds into the decision tree

            if flow is None:

                #if there wasn't a key with the packet going forward
                #there might be one of it going backwards
                direction = PacketDirection.REVERSE
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                flow = self.flows.get(packet_flow_key)

                if flow is None:

                    direction = PacketDirection.FORWARD
                    flow = Flow(packet, direction, interface)
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)

                    #since no key was found in the dictionary in either direction
                    #the key is added with it's corresponding value (flow)
                    self.flows[packet_flow_key] = flow

            elif 1570000000 > (packet.time - flow.latest_timestamp) > .2:

                

                direction = PacketDirection.FORWARD
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                flow = self.flows.get(packet_flow_key)

                if flow is None:

                    direction = PacketDirection.REVERSE
                    flow = Flow(packet, direction, interface)
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)

                    #since no key was found in the dictionary in either direction
                    #the key is added with it's corresponding value (flow)

            flow.add_packet(packet, direction)

        
    def get_flows(self) -> list:
        return self.flows.values()