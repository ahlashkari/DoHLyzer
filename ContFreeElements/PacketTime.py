#!/usr/bin/env python

#for type hinting
from typing import List

#For math stuff
import numpy
from scipy import stats as stat



class PacketTime:
    """This class extracts features related to the Packet Times.

    Attributes:
        count (int): The row number.
        mean_count (int): The number of means.
        grand_total(float): The cummulative total of the means.
        duration_total(float): The cummulative total of the durations.

    """        
    mean_count = 0
    grand_total = 0
    duration_total = 0

    def __init__(self, feature):
        self.feature = feature

    def _get_packet_times(self) -> list:
        """Gets a list of the times of the packets on a flow

        Returns:
            A list of the packet times.

        """
        packet_times = [self.feature.packet.time for self.feature.packet, _ in self.feature.packets]
        return packet_times

    def get_duration(self) -> float:
        """Calculates the duration of a network flow.

        Returns:
            The duration of a network flow.

        """

        return max(self._get_packet_times()) - min(self._get_packet_times())

    def get_duration_total(self) -> float:
        """Addes together all the duration values on a given run.

        Returns:
            The total Duration

        """

        if PacketTime.mean_count == 0:
            PacketTime.duration_total = self.get_duration() - self.get_duration()
        else:
            PacketTime.duration_total += self.get_duration()

        return PacketTime.duration_total

    def get_var(self) -> float:
        """Calculates the variation of packet times in a network Feature.

        Returns:
            float: The variation of packet times.

        """
        return numpy.var(self._get_packet_times())

    def get_std(self) -> float:
        """Calculates the standard deviation of packet times in a network flow.
        
        Rens:
            float: The standard deviation of packet times.

        """
        return numpy.sqrt(self.get_var())

    def get_mean(self) -> float:
        """Calculates the mean of packet times in a network flow.

        Returns:
            float: The mean of packet times

        """
        mean = 0
        if self._get_packet_times() != 0:
            mean = numpy.mean(self._get_packet_times())
        
        return mean

    def _get_grand_total(self) -> None:
        """Calculates the overall total of packet times in a network flow.

        Returns:
            float: The grand total of packet times

        """

        if PacketTime.mean_count == 0:
            PacketTime.grand_total = self.get_mean() - self.get_mean()
        else:
            PacketTime.grand_total += self.get_mean()

        PacketTime.mean_count += 1

        return PacketTime.grand_total

    def get_grand_mean(self) -> float:
        """Calculates the cummulative mean of packet times in a network flow.

        Returns:
            float: The grand mean of packet times


        """

        PacketTime.grand_mean = self._get_grand_total()/(PacketTime.mean_count-1)

        return PacketTime.grand_mean

    def get_median(self) -> float:
        """Calculates the median of packet times in a network flow.

        Returns:
            float: The median of packet times

        """
        return numpy.median(self._get_packet_times())

    def get_mode(self) -> float:
        """The mode of packet times in a network flow.

        Returns:
            float: The mode of packet times

        """
        mode = -1
        if len(self._get_packet_times()) != 0:
            mode = float(stat.mode(self._get_packet_times())[0])
        
        return mode

    def get_skew(self) -> float:
        """Calculates the skew of packet times in a network flow using the median.

        Returns:
            float: The skew of packet times.

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
        """Calculates the skew of the packet times ina network flow using the mode.

        Returns:
            float: The skew of the packet times.
    
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
        """Calculates the coefficient of variance of packet times in a network flow.

        Returns:
            float: The coefficient of variance of a packet times list.

        """
        cov = -1
        if self.get_mean() !=0:
            cov = self.get_std()/self.get_mean()
        
        return cov
