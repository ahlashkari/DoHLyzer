#!/usr/bin/env python
import os
import sys

from enum import Enum, auto
import os
from typing import List, Union, Any

from ContElements.Context.PacketDirection import PacketDirection


class PacketFlowKey:
    def get_packet_flow_key(packet: Any, direction: Enum) -> tuple:
        """Creates a key signature for a packet.

        Summary:
            Creates a key signature for a packet so it can be
            assigned to a flow.

        Args:
            packet: A network packet
            direction: The direction of a packet 
        
        Returns:
            A tuple of the String IPv4 addresses of the destination, 
            the source port as an int,
            the time to live value,
            the window size, and
            TCP flags.

        """
        time = True
        if packet.proto == 6:
            protocol = 'TCP'
        elif packet.proto == 17:
            protocol = 'UDP'
        else:
            raise Exception('Only TCP protocols are supported.')

        if direction == PacketDirection.FORWARD:
            dest_ip = packet['IP'].dst
            src_ip = packet['IP'].src 
            src_port = packet[protocol].sport
            dest_port = packet[protocol].dport
        else:
            dest_ip = packet['IP'].src
            src_ip = packet['IP'].dst
            src_port = packet[protocol].dport
            dest_port = packet[protocol].sport

        return dest_ip, src_ip, src_port, dest_port, time