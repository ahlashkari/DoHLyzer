#!/usr/bin/env python

# standard library imports

import os
import sys

# network sniffing imports
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# internal imports
from meter.ContElements.Context import PacketDirection

# modifying the path to import a sibling
# by going up to the parent directory
sys.path.append(os.path.realpath('..'))

# noinspection PyUnresolvedReferences
from meter.ContFreeElements import PacketTime


# Barks like a dog, bytes like a dog.
class Barks:
    """Extracts features from the traffic related to the bytes in a flow.

    Attributes:
        total_bytes_sent (int): A cummalitve value of the bytes sent.
        total_bytes_received (int): A cummalitve value of the bytes received.
        total_forward_header_bytes (int): A cummalitve value of the bytes \
        sent in the forward direction of the flow.
        total_reverse_header_bytes (int): A cummalitve value of the bytes \
        sent in the reverse direction of the flow.
        row (int) : The row number.

    """

    __slots__ = ['feature']

    def __init__(self, feature):
        self.feature = feature
        
    def direction_list(self) -> list:
        """Returns a list of the directions of the \
        first 50 packets in a flow.

        Return:
            list with packet directions.

        """
        index = 0
        feat = self.feature
        direction_list = [(i, direction.name)[1] for (i, (packet, direction)) in enumerate(feat.packets) if i < 50]
        return direction_list

    def get_bytes_sent(self) -> int:
        """Calculates the amount bytes sent from the machine being used to run DoHlyzer.

        Returns:
            int: The amount of bytes.

        """
        feat = self.feature
        interface = feat.src_ip

        return sum(len(packet) for packet, direction in \
                   feat.packets if direction == PacketDirection.FORWARD)

    def get_sent_rate(self) -> float:
        """Calculates the rate of the bytes being sent in the current flow.

        Returns:
            float: The bytes/sec sent.

        """
        sent = self.get_bytes_sent()
        duration = PacketTime(self.feature).get_duration()

        if duration == 0:
            rate = -1
        else:
            rate = sent / duration

        return rate

    def get_bytes_received(self) -> int:
        """Calculates the amount bytes received.

        Returns:
            int: The amount of bytes.

        """
        packets = self.feature.packets
        interface = self.feature.src_ip

        return sum(len(packet) for packet, direction in
                   packets if direction == PacketDirection.REVERSE)

    def get_received_rate(self) -> float:
        """Calculates the rate of the bytes being received in the current flow.

        Returns:
            float: The bytes/sec received.

        """
        received = self.get_bytes_received()
        duration = PacketTime(self.feature).get_duration()

        if duration == 0:
            rate = -1
        else:
            rate = received / duration

        return rate


    def get_forward_header_bytes(self) -> int:
        """Calculates the amount of header bytes \
        in the header sent in the same direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res

        packets = self.feature.packets

        return sum(header_size(packet) for packet, direction
                   in packets if direction == PacketDirection.FORWARD)

    def get_forward_rate(self) -> int:
        """Calculates the rate of the bytes being going forward
        in the current flow.

        Returns:
            float: The bytes/sec forward.

        """
        forward = self.get_forward_header_bytes()
        duration = PacketTime(self.feature).get_duration()

        if duration > 0:
            rate = forward / duration
        else:
            rate = -1

        return rate

    def get_reverse_header_bytes(self) -> int:
        """Calculates the amount of header bytes \
         in the header sent in the opposite direction as the flow.

        Returns:
            int: The amount of bytes.

        """

        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res

        packets = self.feature.packets

        return sum(header_size(packet) for packet, direction
                   in packets if direction == PacketDirection.REVERSE)


    def get_reverse_rate(self) -> int:
        """Calculates the rate of the bytes being going reverse
        in the current flow.

        Returns:
            float: The bytes/sec reverse.

        """
        reverse = self.get_reverse_header_bytes()
        duration = PacketTime(self.feature).get_duration()

        if duration == 0:
            rate = -1
        else:
            rate = reverse / duration

        return rate

    def get_header_in_out_ratio(self) -> float:
        """Calculates the ratio of foward traffic over reverse traffic.

        Returns:
            float: The ratio over reverse traffic.
            If the reverse header bytes is 0 this returns -1 to avoid
            a possible division by 0.

        """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()

        ratio = -1
        if reverse_header_bytes != 0:
            ratio = forward_header_bytes / reverse_header_bytes

        return ratio


    def get_initial_ttl(self) -> int:
        """Obtains the initial time-to-live value.

        Returns:
            int: The initial ttl value in seconds.

        """
        feat = self.feature
        return [packet['IP'].ttl for packet, _ in
                feat.packets][0]
