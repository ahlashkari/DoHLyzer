#!/usr/bin/env python


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

            expire_updated = 2
            count = 0
            direction = PacketDirection.FORWARD

            #Creates a variable to check
            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            #if there is no forward flow with a count of 0
            if flow is None:

                #there might be one of it in reverse
                direction = PacketDirection.REVERSE
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:

                    #if no flow exists create a new flow
                    direction = PacketDirection.FORWARD
                    flow = Flow(packet, direction, interface)
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow

                elif (packet.time - flow.latest_timestamp) > expire_updated:

                    #if the packet exists in the flow but the packet is sent
                    #after too much of a delay than it is a part of a new flow.
                    expired = expire_updated
                    while (packet.time - flow.latest_timestamp) > expired:

                        count += 1
                        direction = PacketDirection.REVERSE
                        expired += expire_updated
                        packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                        flow = self.flows.get((packet_flow_key, count))

                        if flow is None:
                            flow = Flow(packet, direction, interface)
                            self.flows[(packet_flow_key, count)] = flow
                            break

            elif (packet.time - flow.latest_timestamp) > expire_updated:

                expired = expire_updated
                while (packet.time - flow.latest_timestamp) > expired:

                    count += 1
                    expired += expire_updated
                    direction = PacketDirection.FORWARD
                    packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction, interface)
                        self.flows[(packet_flow_key, count)] = flow
                        break
            
            flow.add_packet(packet, direction)

    def get_flows(self) -> list:
        return self.flows.values()
