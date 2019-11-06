#!/usr/bin/env python

from enum import Enum, auto

class PacketDirection(Enum):
    """ Packet Direction creates constants for the direction of the packets.
    
    There are two given directions that the packets can Feature along
    the line. PacketDirection is an enumeration with the values
    foward (0) and reverse (1).
    """

    FORWARD = auto()
    REVERSE = auto()
    