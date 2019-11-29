#!/usr/bin/env python

from itertools import groupby

#internal imports
from Flow import Flow
from ContElements.Context.PacketDirection import PacketDirection
from ContElements.Context import PacketFlowKey

EXPIRED_UPDATE = 40

class FlowList:
    """Creates a list of network flows.

    """
    def __init__(self, interface, packets, csv_writer) -> None:
        # local_mac = get_if_hwaddr(interface)
        self.flows = {}
        self.csv_line = 0

        for index, packet in enumerate(packets):
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

                elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                    #If the packet exists in the flow but the packet is sent
                    #after too much of a delay than it is a part of a new flow.
                    expired = EXPIRED_UPDATE
                    while (packet.time - flow.latest_timestamp) > expired:

                        count += 1
                        expired += EXPIRED_UPDATE
                        flow = self.flows.get((packet_flow_key, count))

                        if flow is None:
                            flow = Flow(packet, direction, interface)
                            self.flows[(packet_flow_key, count)] = flow
                            break

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:

                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction, interface)
                        self.flows[(packet_flow_key, count)] = flow
                        break

            flow.add_packet(packet, direction)
            if i % 100 == 99:
                garbage_collect(packet.time, csv_writer)

        garbage_collect(None, csv_writer)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(latest_time, csv_writer) -> None:
        print('Garbage Collection Began. Flows = {}'.format(len(flows)))
        keys = self.flows.keys()
        for k in keys:
            flow = self.flows.pop(k)
            if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE:
                if self.csv_line == 0:
                    writer.writerow(flow.get_data().keys())
                writer.writerow(flow.get_data().values())
                self.csv_line += 1
        print('Garbage Collection Finished. Flows = {}'.format(len(flows)))


