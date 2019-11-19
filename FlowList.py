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



class FlowList:
    """Creates a list of network flows.

    """
    def __init__(self, interface, packets) -> None:
        # local_mac = get_if_hwaddr(interface)
        self.flows = {}

        for packet in packets:
            
            count = 0
            direction = PacketDirection.FORWARD

            #Creates a variable to check
            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
            # self._expired(packet, flow, packet_flow_key, 2)

            #if there is no forward flow with a count of 0
            if flow is None:

                #there might be one of it in reverse
                direction = PacketDirection.REVERSE
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                flow = self.flows.get((packet_flow_key, count))
                
                # self._expired(packet, flow, packet_flow_key, 2)
                          
                if flow is None:

                    #if no flow exists create a new flow
                    direction = PacketDirection.FORWARD
                    flow = Flow(packet, direction, interface)
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow

                elif (packet.time - flow.latest_timestamp) > 0.2:

                    #if the packet exists in the flow but the packet is sent
                    #after too much of a delay than it is a part of a new flow.
                    expired = 0.2
                    while (packet.time - flow.latest_timestamp) > expired:

                        count += 1
                        expired += 0.2

                        direction = PacketDirection.REVERSE
                        packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                        flow = self.flows.get((packet_flow_key, count))
                        if flow is None:
                            flow = Flow(packet, direction, interface)
                            self.flows[(packet_flow_key, count)] = flow
                            break

                    if flow is None:
                        #Now we are checking the flow in the forward direction
                        #with the count of one
                        direction = PacketDirection.FORWARD
                        packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                        flow = self.flows.get((packet_flow_key, count))

                        if flow is None:
                            flow = Flow(packet, direction, interface)
                            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                            self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > 0.2:
                count += 1
                direction = PacketDirection.FORWARD
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    direction = PacketDirection.REVERSE
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        direction = PacketDirection.FORWARD
                        flow = Flow(packet, direction, interface)
                        packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow



            print("flow.latest_timestamp {} - packet.time {} = {}".format(flow.latest_timestamp, packet.time, packet.time - flow.latest_timestamp))
            flow.add_packet(packet, direction)


        
    def get_flows(self) -> list:
        return self.flows.values()

    def _expired(self, packet, flow, key, expiration):
        pass

            

