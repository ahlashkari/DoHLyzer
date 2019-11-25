#!/usr/bin/env python

from itertools import groupby

#internal imports
from Flow import Flow
from ContElements.Context.PacketDirection import PacketDirection
from ContElements.Context import PacketFlowKey



class FlowList:
    """Creates a list of network flows.

    """
    def __init__(self, interface, packets) -> None:
        # local_mac = get_if_hwaddr(interface)
        self.flows = {}
        for packet in packets:

            expire_update = 40
            count = 0
            direction = PacketDirection.FORWARD

            #Creates a key variable to check
            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            #If there is no forward flow with a count of 0
            if flow is None:
                #There might be one of it in reverse
                direction = PacketDirection.REVERSE
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    #If no flow exists create a new flow
                    direction = PacketDirection.FORWARD
                    flow = Flow(packet, direction, interface)
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow

                elif (packet.time - flow.latest_timestamp) > expire_update:
                    #If the packet exists in the flow but the packet is sent
                    #after too much of a delay than it is a part of a new flow.
                    expired = expire_update
                    while (packet.time - flow.latest_timestamp) > expired:

                        count += 1
                        expired += expire_update
                        flow = self.flows.get((packet_flow_key, count))

                        if flow is None:
                            flow = Flow(packet, direction, interface)
                            self.flows[(packet_flow_key, count)] = flow
                            break

            elif (packet.time - flow.latest_timestamp) > expire_update:
                expired = expire_update
                while (packet.time - flow.latest_timestamp) > expired:

                    count += 1
                    expired += expire_update
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction, interface)
                        self.flows[(packet_flow_key, count)] = flow
                        break

            flow.add_packet(packet, direction)

    def get_flows(self) -> list:
        return self.flows.values()
