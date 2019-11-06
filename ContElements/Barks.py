#!/usr/bin/env python

#standard library imports

import os
import sys

#network sniffing imports
from scapy.all import get_if_hwaddr
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

#internal imports
from ContElements.Context.PacketFlowKey import PacketFlowKey
from ContElements.Context.PacketDirection import PacketDirection

#modifying the path to import a sibling
#by going up to the parent directory
sys.path.append(os.path.realpath('..'))

from ContFreeElements.PacketTime import PacketTime



#Barks like a dog, bytes like a dog.    
class Barks:
    """Extracts features from the traffic related to the bytes in a flow.

    Attributes:
        total_bytes_sent (int): A cummalitve value of the bytes sent.
        sent_count (int): The row number used in total sent method.
        total_bytes_received (int): A cummalitve value of the bytes received.
        received_count (int):The row number used in  total received method.
        total_forward_header_bytes (int): A cummalitve value of the bytes sent in the forward direction of the flow.
        forward_count (int): The count of the forward traffic.
        total_reverse_header_bytes (int): A cummalitve value of the bytes sent in the reverse direction of the flow.
        reverse_count (int): The count of the forward traffic.

    """
    total_bytes_sent = 0
    sent_count = 0

    total_bytes_received = 0
    received_count = 0

    total_forward_header_bytes = 0
    forward_count = 0

    total_reverse_header_bytes = 0
    reverse_count = 0

    def __init__(self, feature):
        self.feature = feature 

    def get_bytes_sent(self) -> int:
        """The amount bytes sent from the machine being used to run DoHlyzer.

        Returns:
            int: The amount of bytes.

        """
        feat = self.feature
        interface = get_if_hwaddr(self.feature.interface)

        return sum(len(packet) for packet, _ in  \
            feat.packets if packet.src == interface)

    def get_sent_rate(self) -> int:
        """Calculates the rate of the bytes being sent in the current flow.

        Returns:
            float: The bytes/sec sent.

        """
        sent = self.get_bytes_sent()
        duration = PacketTime(self.feature).get_duration()

        rate = sent / duration

        return rate


    def get_total_bytes_sent(self) -> int:
        """The total bytes sent in the sniffing session.

        Returns:
            int: The total amount of bytes

        """


        if Barks.sent_count == 0:
            Barks.total_bytes_sent = self.get_bytes_sent() - self.get_bytes_sent()
        else:
            Barks.total_bytes_sent += self.get_bytes_sent()

        Barks.sent_count += 1

        return Barks.total_bytes_sent

    def get_bytes_received(self) -> int:
        """The amount bytes sent to the machine being used to run this DoHlyzer.
        
        Returns:
            int: The amount of bytes.

        """
        packets = self.feature.packets
        interface = get_if_hwaddr(self.feature.interface)

        return sum(len(packet) for packet, _ in \
            packets if packet.src != interface)

    def get_received_rate(self) -> int:
        """Calculates the rate of the bytes being received in the current flow.

        Returns:
            float: The bytes/sec received.

        """
        received = self.get_bytes_received()
        duration = PacketTime(self.feature).get_duration()

        rate = received / duration

        return rate

    def get_total_bytes_received(self) -> int:
        """The total bytes received in the sniffing session.

        Returns:
            int: The total amount of bytes

        """
    

        if Barks.received_count == 0:
            Barks.total_bytes_received = self.get_bytes_received() - self.get_bytes_received()
        else:
            Barks.total_bytes_received += self.get_bytes_received()

        Barks.received_count += 1

        return Barks.total_bytes_received

    def get_forward_header_bytes(self) -> int:
        """The amount of header bytes in the header sent in the same direction as the flow.
        
        Returns:
            int: The amount of bytes.
            
        """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res

        packets = self.feature.packets

        return sum(header_size(packet) for packet, direction \
            in packets if direction == PacketDirection.FORWARD)

    def get_forward_rate(self) -> int:
        """Calculates the rate of the bytes being going forward
        in the current flow.

        Returns:
            float: The bytes/sec forward.

        """
        forward = self.get_forward_header_bytes()
        duration = PacketTime(self.feature).get_duration()

        rate = forward / duration

        return rate

    def get_total_forward_bytes(self) -> int:
        """The total bytes in the header going forward.

        Returns:
            int: The total amount of bytes

        """

        if Barks.forward_count == 1:
            Barks.total_forward_header_bytes = self.get_forward_header_bytes() \
                - self.get_forward_header_bytes()
        else:
            Barks.total_forward_header_bytes += self.get_forward_header_bytes()

        Barks.forward_count += 1

        return Barks.total_forward_header_bytes

    def get_reverse_header_bytes(self) -> int:
        """The amount of header bytes in the header sent in the opposite direction as the flow.
        
        Returns:
            int: The amount of bytes.
            
        """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res

        packets = self.feature.packets

        return sum(header_size(packet) for packet, direction \
            in packets if direction == PacketDirection.REVERSE)

    def get_total_reverse_bytes(self) -> int:
        """The total reverse header bytes

        Returns:
            int: The total amount of bytes

        """
        #global total_reverse_header_bytes
        #global reverse_count

        if Barks.reverse_count == 1:
            Barks.total_reverse_header_bytes = self.get_reverse_header_bytes() \
                - self.get_reverse_header_bytes()
        else:
            Barks.total_reverse_header_bytes += self.get_reverse_header_bytes()

        Barks.reverse_count += 1

        return Barks.total_reverse_header_bytes

    def get_reverse_rate(self) -> int:
        """Calculates the rate of the bytes being going reverse
        in the current flow.

        Returns:
            float: The bytes/sec reverse.

        """
        reverse = self.get_reverse_header_bytes()
        duration = PacketTime(self.feature).get_duration()

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
            ratio = forward_header_bytes/reverse_header_bytes
        
        return ratio

    def get_total_header_in_out_ratio(self) -> float:
        """Calculates the ratio of foward traffic over reverse traffic.

        Returns:
            float: The ratio over reverse traffic.
            If the reverse header bytes is 0 this returns -1 to avoid /
            a possible division by 0.

        """
        reverse_header_bytes = self.get_total_reverse_bytes()
        forward_header_bytes = self.get_total_forward_bytes()

        ratio = -1
        if reverse_header_bytes != 0:
            ratio = forward_header_bytes/reverse_header_bytes
        
        return ratio