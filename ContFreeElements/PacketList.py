from ContFreeElements.PacketLength import PacketLength
from ContFreeElements.PacketTime import PacketTime

class PacketList:
    def __init__(self, packets):
        self.packets = packets

    def relative_time_list(self):
        time_list = []

        i = 0
        while i < 50:
            if i == 0:
                time_list.append(self.packets[i].time)
            elif packet.time is not None:
                time_list.append(self.packets[i].time-self.packets[i-1].time)
            else:
                time_list.append(0)
            i += 1


        return time_list