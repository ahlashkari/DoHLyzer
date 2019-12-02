#!/usr/bin/env python

#For type hinting and making things easier to handle
from enum import Enum
from typing import Any

#Supressing warnings due to the dynamic nature of the program
#aka: numpy freaks out
import warnings


#internal imports

from ContElements.Barks import Barks
from ContElements.TimeDiff import TimeDiff

from ContElements.Context import PacketFlowKey

from ContFreeElements.Flags import Flags
from ContFreeElements.IpBased import IpBased
from ContFreeElements.PacketLength import PacketLength
from ContFreeElements.PacketTime import PacketTime



warnings.filterwarnings("ignore")


class Flow:
    """This class summarizes the values of the features of the network flows.

    """

    def __init__(self, packet: Any, direction: Enum, interface="enp0s3") -> None:
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
            interface (Any): What is being used to capture the network traffic. TODO: remove this

        """

        self.dest_ip, self.src_ip, self.src_port, self.dest_port = \
            PacketFlowKey.get_packet_flow_key(packet, direction)

        self.packets = []
        self.interface = interface
        self.latest_timestamp = 0


    def get_data(self) -> dict:
        """This method obtains the values of the features extracted from each flow.

        Note:
            Only some of the network data plays well together in this list.
            Time-to-live values, window values, and flags cause the data to seperate out too
            much.

        Returns:
           list: returns a List of values to be ouputted into a csv file.

        """

        barks = Barks(self)
        flags = Flags(self)
        ip = IpBased(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        time = TimeDiff(self)


        return {
            'SourceIP' : self.src_ip,
            'DestinationIP' : self.dest_ip,
            'SourcePort' : self.src_port,
            'DestinationPort' : self.dest_port,
            'RelativeTimeList' : packet_time.relative_time_list(),
            'PacketSizeList' : packet_length.first_fifty(),
            'DirectionList' : barks.direction_list(),
            'TimeStamp' : packet_time.get_time_stamp(),
            'Duration' : packet_time.get_duration(),
            'DurationTotal' : packet_time.get_duration_total(),
            'FlowBytesSent' : barks.get_bytes_sent(),
            'FlowSentRate' : barks.get_sent_rate(),
            'TotalBytesSent' : barks.get_total_bytes_sent(),
            'FlowBytesReceived' : barks.get_bytes_received(),
            'FlowReceivedRate' : barks.get_received_rate(),
            'TotalBytesReceived' : barks.get_total_bytes_received(),
            'ForwardHeaderBytes' : barks.get_forward_header_bytes(),
            'ForwardHeaderRate' : barks.get_forward_rate(),
            'TotalForwardHeaderBytes' : barks.get_total_forward_bytes(),
            'ReverseHeaderBytes' : barks.get_reverse_header_bytes(),
            'ReverseHeaderRate' : barks.get_reverse_rate(),
            'TotalReverseHeaderBytes' : barks.get_total_reverse_bytes(),
            'HeaderInOutRatio' : barks.get_header_in_out_ratio(),
            'TotalHeaderInOutRatio' : barks.get_total_header_in_out_ratio(),
            'InitialTTL' : barks.get_initial_ttl(),
            'FirstPacketSize' : packet_length.get_first_packet_length(),
            'PacketLengthVariance' : packet_length.get_var(),
            'PacketLengthStandardDeviation' : packet_length.get_std(),
            'PacketLengthMean' : packet_length.get_mean(),
            'PacketLengthGrandMean' : packet_length.get_grand_mean(),
            'PacketLengthMedian' : packet_length.get_median(),
            'PacketLengthMode' : packet_length.get_mode(),
            'PacketLengthSkewFromMedian' : packet_length.get_skew(),
            'PacketLengthSkewFromMode' : packet_length.get_skew2(),
            'PacketLengthCoefficientofVariation' : packet_length.get_cov(),
            'PacketTimeVariance' : packet_time.get_var(),
            'PacketTimeStandardDeviation' : packet_time.get_std(),
            'PacketTimeMean' : packet_time.get_mean(),
            'PacketTimeGrandMean' : packet_time.get_grand_mean(),
            'PacketTimeMedian' : packet_time.get_median(),
            'PacketTimeMode' : packet_time.get_mode(),
            'PacketTimeSkewFromMedian' : packet_time.get_skew(),
            'PacketTimeSkewFromMode' : packet_time.get_skew2(),
            'PacketTimeCoefficientofVariation' : packet_time.get_cov(),
            'FlowDifferenceTimeVariance' : time.get_var(),
            'FlowDifferenceTimeStandardDeviation' : time.get_std(),
            'FlowDifferenceTimeMean' : time.get_mean(),
            'FlowDifferenceTimeGrandMean' : time.get_grand_mean(),
            'FlowDifferenceTimeMedian' : time.get_median(),
            'FlowDifferenceTimeMode' : time.get_mode(),
            'FlowDifferenceTimeSkewFromMedian' : time.get_skew(),
            'FlowDifferenceTimeSkewFromMode' : time.get_skew2(),
            'FlowDifferenceTimeCoefficientofVariation' : time.get_cov(),
            'IsGoogle' : ip.is_google(),
            'IsMalwareIP' : ip.is_bad(),
            'FlagTotal' : flags.get_flag_total(),
            'NullFlagCount' : flags.get_null_count(),
            'PureFINCount' : flags.get_fin_count(),
            'EmbeddedFINCount' : flags.get_emb_fin_count(),
            'PureSYNCount' : flags.get_syn_count(),
            'EmbeddedSYNCount' : flags.get_emb_syn_count(),
            'PureRSTCount' : flags.get_rst_count(),
            'EmbeddedRSTCount' : flags.get_emb_rst_count(),
            'PurePSHCount' : flags.get_psh_count(),
            'EmbeddedPSHCount' : flags.get_emb_psh_count(),
            'PureACKCount' : flags.get_ack_count(),
            'EmbeddedACKCount' : flags.get_emb_ack_count(),
            'PureURGCount' : flags.get_urg_count(),
            'EmbeddedURGCount' : flags.get_emb_urg_count(),
            'PureECECount' : flags.get_ece_count(),
            'EmbeddedECECount' : flags.get_emb_ece_count(),
            'PureCWRCount' : flags.get_cwr_count(),
            'EmbeddedCWRCount' : flags.get_emb_cwr_count(),
            'RSTACKCount' : flags.get_rstack_count(),
            'SYNACKCount' : flags.get_synack_count(),
            'PushACKCount' : flags.get_pshack_count(),
            'SynFinCount' : flags.get_synfin_count(),
            'EmbeddedSynFin' : flags.get_contain_finsyn_count(),
        }

    def add_packet(self, packet, direction) -> None:
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be added to a flow
            direction: The direction the packet is going in that flow

        """
        self.packets.append((packet, direction))

        self.latest_timestamp = max([packet.time, self.latest_timestamp])
            