#!/usr/bin/env python

# Supressing warnings due to the dynamic nature of the program
# aka: numpy freaks out
import warnings
# For type hinting and making things easier to handle
from enum import Enum
from typing import Any

# internal imports
from meter import constants
from meter.ContElements.Barks import Barks
from meter.ContElements.Context import PacketFlowKey
from meter.ContElements.ResponseTime import ResponseTime
from meter.ContFreeElements import PacketLength
from meter.ContFreeElements import PacketTime

warnings.filterwarnings("ignore")


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Any, direction: Enum):
        """This method initializes an object from the Flow class.

        Args:
            packet (Any): A packet from the network.
            direction (Enum): The direction the packet is going ove the wire.
        """

        self.dest_ip, self.src_ip, self.src_port, self.dest_port = \
            PacketFlowKey.get_packet_flow_key(packet, direction)

        self.packets = []
        self.latest_timestamp = 0
        self.start_timestamp = 0

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
        # flags = Flags(self)
        # ip = IpBased(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        response = ResponseTime(self)
        # tls = TlsInfo(self)

        data = {
            # Basic IP information
            'SourceIP': self.src_ip,
            'DestinationIP': self.dest_ip,
            'SourcePort': self.src_port,
            'DestinationPort': self.dest_port,

            # Hello exchange information
            #'ClientCipherSuit': tls.client_cipher_suit(),
            #'ClientHelloMessageLength': tls.client_hello_msglen(),
            #'ServerHelloMessageLength': tls.server_hello_msglen(),

            #'Compression': tls.compression(),
            #'SessionLifetime': tls.session_lifetime(),

            # Information based on first 50 packets
            #'RelativeTimeList': packet_time.relative_time_list(),
            #'PacketSizeList': packet_length.first_fifty(),
            #'DirectionList': barks.direction_list(),

            # Basic information from packet times
            'TimeStamp': packet_time.get_time_stamp(),
            'Duration': packet_time.get_duration(),
            # 'DurationTotal' : packet_time.get_duration_total(),

            # Information based and extrapolaited from the amount of bytes
            'FlowBytesSent': barks.get_bytes_sent(),
            'FlowSentRate': barks.get_sent_rate(),
            'FlowBytesReceived': barks.get_bytes_received(),
            'FlowReceivedRate': barks.get_received_rate(),
            #'ForwardHeaderBytes': barks.get_forward_header_bytes(),
            #'ForwardHeaderRate': barks.get_forward_rate(),
            #'ReverseHeaderBytes': barks.get_reverse_header_bytes(),
            #'ReverseHeaderRate': barks.get_reverse_rate(),
            #'HeaderInOutRatio': barks.get_header_in_out_ratio(),
            #'InitialTTL': barks.get_initial_ttl(),

            # Statistical info extrapolaited and obtained from Packet lengths
            'PacketLengthVariance': packet_length.get_var(),
            'PacketLengthStandardDeviation': packet_length.get_std(),
            'PacketLengthMean': packet_length.get_mean(),
            # 'PacketLengthGrandMean' : packet_length.get_grand_mean(),
            'PacketLengthMedian': packet_length.get_median(),
            'PacketLengthMode': packet_length.get_mode(),
            'PacketLengthSkewFromMedian': packet_length.get_skew(),
            'PacketLengthSkewFromMode': packet_length.get_skew2(),
            'PacketLengthCoefficientofVariation': packet_length.get_cov(),

            # Statistical info extrapolaited and obtained from Packet times
            'PacketTimeVariance': packet_time.get_var(),
            'PacketTimeStandardDeviation': packet_time.get_std(),
            'PacketTimeMean': packet_time.get_mean(),
            'PacketTimeMedian': packet_time.get_median(),
            'PacketTimeMode': packet_time.get_mode(),
            'PacketTimeSkewFromMedian': packet_time.get_skew(),
            'PacketTimeSkewFromMode': packet_time.get_skew2(),
            'PacketTimeCoefficientofVariation': packet_time.get_cov(),

            # Response Time
            'ResponseTimeTimeVariance': response.get_var(),
            'ResponseTimeTimeStandardDeviation': response.get_std(),
            'ResponseTimeTimeMean': response.get_mean(),
            'ResponseTimeTimeMedian': response.get_median(),
            'ResponseTimeTimeMode': response.get_mode(),
            'ResponseTimeTimeSkewFromMedian': response.get_skew(),
            'ResponseTimeTimeSkewFromMode': response.get_skew2(),
            'ResponseTimeTimeCoefficientofVariation': response.get_cov(),

            # Information extrapolaited from the ip_addresses
            #'IsGoogle': ip.is_google(),
            #'IsMalwareIP': ip.is_bad(),

            # Information about the packet flags
            #'FlagTotal': flags.get_flag_total(),
            #'NullFlagCount': flags.get_null_count(),
            #'PureFINCount': flags.get_fin_count(),
            #'EmbeddedFINCount': flags.get_emb_fin_count(),
            #'PureSYNCount': flags.get_syn_count(),
            #'EmbeddedSYNCount': flags.get_emb_syn_count(),
            #'PureRSTCount': flags.get_rst_count(),
            #'EmbeddedRSTCount': flags.get_emb_rst_count(),
            #'PurePSHCount': flags.get_psh_count(),
            #'EmbeddedPSHCount': flags.get_emb_psh_count(),
            #'PureACKCount': flags.get_ack_count(),
            #'EmbeddedACKCount': flags.get_emb_ack_count(),
            #'PureURGCount': flags.get_urg_count(),
            #'EmbeddedURGCount': flags.get_emb_urg_count(),
            #'PureECECount': flags.get_ece_count(),
            #'EmbeddedECECount': flags.get_emb_ece_count(),
            #'PureCWRCount': flags.get_cwr_count(),
            #'EmbeddedCWRCount': flags.get_emb_cwr_count(),
            #'RSTACKCount': flags.get_rstack_count(),
            #'SYNACKCount': flags.get_synack_count(),
            #'PushACKCount': flags.get_pshack_count(),
            #'SynFinCount': flags.get_synfin_count(),
            #'EmbeddedSynFin': flags.get_contain_finsyn_count(),

            # TLS extensions
            #'Alpn': tls.alpn(),
            #'Cookie': tls.cookie(),
            #'Csr': tls.csr(),
            #'EarlyData': tls.early_data(),
            #'Heartbeat': tls.heartbeat(),
            #'KeyShare': tls.keyshare(),
            #'KeyShareCH': tls.keyshare_ch(),
            #'MasterSecret': tls.master_secret(),
            #'MaxFrag': tls.max_frag(),
            #'Padding': tls.padding(),
            #'PostHandShakeAuth': tls.post_handshake_auth(),
            #'PreSharedKey': tls.pre_shared_key(),
            #'PskKeyExch': tls.psk_key_exch(),
            #'RecordSizeLimit': tls.record_size_limit(),
            #'Renegotiation': tls.renegotiation(),
            #'ServerName': tls.server_name(),
            #'SessionTicket': tls.session_ticket(),
            #'SignatureAlgorithm': tls.signature_algorithm(),
            #'SupportedGroups': tls.sup_groups(),
            #'SupportedPointFormat': tls.supported_point_format(),
            #'SupportedVersion': tls.supported_version(),
            #'SupportedCh': tls.supported_version_ch(),
            'DoH': self.is_doh(),
        }

        return data

    def add_packet(self, packet, direction) -> None:
        """Adds a packet to the current list of packets.

        Args:
            packet: Packet to be added to a flow
            direction: The direction the packet is going in that flow

        """
        self.packets.append((packet, direction))

        self.latest_timestamp = max([packet.time, self.latest_timestamp])

        if self.start_timestamp == 0:
            self.start_timestamp = packet.time

    def is_doh(self) -> bool:
        return self.src_ip in constants.DOH_IPS or self.dest_ip in constants.DOH_IPS

    @property
    def duration(self):
        return self.latest_timestamp - self.start_timestamp
