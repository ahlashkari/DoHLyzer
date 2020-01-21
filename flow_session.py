#!/usr/bin/env python
import csv
# internal imports
import os

from scapy.sessions import DefaultSession

from ContElements.Context import PacketFlowKey
from ContElements.Context.PacketDirection import PacketDirection
from Flow import Flow
from time_series.processor import Processor

EXPIRED_UPDATE = 40


class FlowSession(DefaultSession):
    """Creates a list of network flows.

    """

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0

        if self.output_mode == 'flow':
            output = open(self.output_file, 'w')
            self.csv_writer = csv.writer(output)

        self.packets_count = 0

        super(FlowSession, self).__init__(None, True, *args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        self.packets_count += 1
        count = 0
        direction = PacketDirection.FORWARD

        # Creates a key variable to check
        packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
        flow = self.flows.get((packet_flow_key, count))

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

            if flow is None:
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = PacketFlowKey.get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))

                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:

                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)

        if self.packets_count % 10000 == 0:
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        print('Garbage Collection Began. Flows = {}'.format(len(self.flows)))
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)

            if self.output_mode == 'flow':
                if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE:
                    data = flow.get_data()
                    if self.csv_line == 0:
                        self.csv_writer.writerow(data.keys())
                    self.csv_writer.writerow(data.values())
                    self.csv_line += 1
                    del self.flows[k]
            else:
                if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE:
                    output_dir = os.path.join(self.output_file, 'doh' if flow.is_doh() else 'ndoh')
                    proc = Processor(flow)
                    for s in proc.generate_segments():
                        s.to_json_file(output_dir, 'data.json')  # Todo: change with output
                    del self.flows[k]
        print('Garbage Collection Finished. Flows = {}'.format(len(self.flows)))


def generate_session_class(output_mode, output_file):
    return type('NewFlowSession', (FlowSession,), {
        'output_mode': output_mode,
        'output_file': output_file,
    })
