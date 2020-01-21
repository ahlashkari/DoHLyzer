import json
import os

from scapy.layers.tls.record import TLSApplicationData

import constants
from ContElements.Context.PacketDirection import PacketDirection


class Clump:
    """Represents several packets with the same direction with short time between them"""

    def __init__(self, direction):
        self.direction = direction
        self.packets = 0
        self.size = 0
        self.latest_timestamp = 0
        self.first_timestamp = 0

    def add_packet(self, packet):
        if self.first_timestamp == 0:
            self.first_timestamp = packet.time
        self.packets += 1
        self.size += len(packet[TLSApplicationData])
        self.latest_timestamp = packet.time

    def accepts(self, packet, direction):
        if direction != self.direction:
            return False
        if self.latest_timestamp != 0 and packet.time - self.latest_timestamp > constants.CLUMP_TIMEOUT:
            return False
        return True

    def duration(self):
        return self.latest_timestamp - self.first_timestamp


class FlowSegment:
    """Represents a segment of a Flow"""

    def __init__(self, flow, clumps):
        self.flow = flow
        self.clumps = clumps

    def output(self):
        duration = []
        size = []
        packets = []
        direction = []

        for c in self.clumps:
            duration.append(float(c.duration()))
            size.append(c.size)
            packets.append(c.packets)
            if c.direction is not None:
                direction.append(1 if c.direction == PacketDirection.FORWARD else -1)
            else:
                direction.append(0)

        return {
            'duration': duration,
            'size': size,
            'packets': packets,
            'direction': direction,
        }

    def to_json_file(self, directory, preferred_name=None):
        preferred_name = preferred_name or '{}_{}-{}_{}.json'.format(self.flow.src_ip, self.flow.src_port,
                                                                     self.flow.dest_ip, self.flow.dest_port)
        file_path = os.path.join(directory, preferred_name)

        if os.path.exists(file_path):
            f = open(file_path, 'r')
            contents = json.load(f)
            contents.append(self.output())
            f.close()
        else:
            contents = [self.output()]

        f = open(file_path, 'w')

        json.dump(contents, f, indent=2)
        f.close()
