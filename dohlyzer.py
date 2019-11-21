#!/usr/bin/env python


import csv
#from enum import Enum, auto

from scapy.all import sniff #, get_if_list, get_if_hwaddr


#internal imports
from FlowList import FlowList


SNIFFED_PACKET_COUNT = 5000
filename = 'output-https.csv'



if __name__ == '__main__':

    ## Below is the commentted out functionality to choose a different interface
    ## to capture packets
    ## enp0s3 is simply the one that has worked best so far.
    #options = get_if_list()

    # print("Please choose which interface you wish to analyze:")
    # for i, interface in enumerate(options):
    #     print("({}) {}".format(i + 1, interface))

    # user_entry = int(input()) - 1

    # user_choice = options[user_entry]

    #print("Capturing packets from `{}` interface...".format(user_choice))

    #set count to 0 to get data continuously until this program is interupted
    #in the terminal with ctrl-c
    #replace iface with offline="<filename>"

    print("Capturing packets from enp0s3 interface...")
    #packets = sniff(offline = 'test.pcap', filter='tcp port 443', prn=lambda x: x.summary())
    packets = sniff(iface='enp0s3', filter='port 443', \
    count=SNIFFED_PACKET_COUNT, prn=lambda x: x.summary())

    flow_list = FlowList('enp0s3', packets)

    with open(filename, 'w') as output:

        writer = csv.writer(output)
        #outputs the feature name for the headers of the csv file

        for index, flow in enumerate(flow_list.get_flows()):
            if index == 0:
                writer.writerow(flow.get_data().keys())
                writer.writerow(flow.get_data().values())
            else:
                writer.writerow(flow.get_data().values())
                