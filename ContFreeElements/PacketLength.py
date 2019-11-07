#!/usr/bin/env python

#For math stuff
import numpy
from scipy import stats as stat

#for type hinting
from typing import List



class PacketLength:
    """This class extracts features related to the Packet Lengths.

    Attributes:
        mean_count (int): The row number.
        grand_total (float): The cummulative total of the means.

    """
    mean_count = 0
    grand_total = 0

    def __init__(self, feature):
        self.feature = feature

    def get_packet_length(self) -> List[int]:
        """Creates a list of packet lengths.
        
        Returns:
            packet_lengths (List[int]):

        """
        packet_lengths = []
        for packet, _ in self.feature.packets:
            packet_lengths.append(len(packet))

        return packet_lengths 

    def get_var(self) -> float:
        """The variation of packet lengths in a network Feature.

        Returns:
            float: The variation of packet lengths.

        """
        return numpy.var(self.get_packet_length())

    def get_std(self) -> float:
        """The standard deviation of packet lengths in a network flow.
        
        Rens:
            float: The standard deviation of packet lengths.

        """
        return numpy.sqrt(self.get_var())

    def get_mean(self) -> float:
        """The mean of packet lengths in a network flow.

        Returns:
            float: The mean of packet lengths.

        """
        mean = 0
        if self.get_packet_length() != 0:
            mean = numpy.mean(self.get_packet_length())
        
        return mean

    def _get_grand_total(self) -> float:
        """The cummulative total of the packet length means in a network flow.

        Returns:
            float: The cummulative total of packet length means
        """        
        if PacketLength.mean_count == 0:
            PacketLength.grand_total = self.get_mean() - self.get_mean()
        else:
            PacketLength.grand_total += self.get_mean()

        PacketLength.mean_count += 1

        return PacketLength.grand_total

    def get_grand_mean(self) -> float:
        """The mean of means of packet lengths in a network flow.

        Returns:
            float: The grand mean of packet lengths.

        """
        PacketLength.grand_mean = -1
        if PacketLength.mean_count > 1:
            PacketLength.grand_mean = self._get_grand_total()/(PacketLength.mean_count-1)

        return PacketLength.grand_mean

    def get_median(self) -> float:
        """The median of packet lengths in a network flow.

        Returns:
            float: The median of packet lengths.

        """
        return numpy.median(self.get_packet_length())

    def get_mode(self) -> float:
        """The mode of packet lengths in a network flow.

        Returns:
            float: The mode of packet lengths.

        """
        mode = -1
        if len(self.get_packet_length()) != 0:
            mode = int(stat.mode(self.get_packet_length())[0])
        
        return mode

    def get_skew(self) -> float:
        """The skew of packet lengths in a network flow using the median.

        Returns:
            float: The skew of packet lengths.

        """
        mean = self.get_mean()
        median = self.get_median()
        dif = 3*(mean - median)
        std = self.get_std()

        skew = -10        
        if std != 0:
            skew = dif/std

        return skew

    def get_skew2(self) -> float:
        """The skew of the packet lengths ina network flow using the mode.

        Returns:
            float: The skew of the packet lengths.
    
        """
        mean = self.get_mean()
        mode = self.get_mode()
        dif = (mean - mode)
        std = self.get_std()

        skew2 = -10        
        if std != 0:
            skew2 = dif/std
        
        return skew2

    def get_cov(self) -> float:
        """The coefficient of variance of packet lengths in a network flow.

        Returns:
            float: The coefficient of variance of a packet lengths list.

        """
        cov = -1
        if self.get_mean() !=0:
            cov = self.get_std()/self.get_mean()
        
        return cov