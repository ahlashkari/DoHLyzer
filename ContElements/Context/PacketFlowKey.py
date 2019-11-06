#!/usr/bin/env python

from enum import Enum, auto
import os
from typing import List, Union, Any

from ContElements.Context.PacketDirection import PacketDirection

class PacketFlowKey:
    def get_packet_flow_key(packet: Any, direction: Enum) -> Any:
        """Extracts the data from packets into more user readable information.

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

        #Try adding raw data here
        if packet.proto == 6:
            protocol = 'TCP'
        else:
            raise Exception('Only TCP protocols are supported.')

        if direction == PacketDirection.FORWARD:
            dest_ip = packet['IP'].dst
            src_ip = packet['IP'].src 
            src_port = packet[protocol].sport
            #flags = packet['TCP'].flags
        else:
            dest_ip = packet['IP'].src
            src_ip = packet['IP'].dst
            src_port = packet[protocol].dport
            #flags = packet['TCP'].flags

        #TCP window measured usually in bytes
        #window = packet['TCP'].window

        return dest_ip, src_ip, src_port