#!/usr/bin/env python

#internal imports
from Features import Features
from FlowList import FlowList
import csv
from enum import Enum, auto

from scapy.all import sniff, get_if_list, get_if_hwaddr
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


SNIFFED_PACKET_COUNT = 5000
filename = 'output-https2.csv'

if __name__ == '__main__':
    options = get_if_list()

    print("Please choose which interface you wish to analyze:")
    for i, interface in enumerate(options):
        print("({}) {}".format(i + 1, interface))

    user_entry = int(input()) - 1

    user_choice = options[user_entry]

    print("Capturing packets from `{}` interface...".format(user_choice))

    #set count to 0 to get data continuously until this program is interupted 
    #in the terminal with ctrl-c
    packets = sniff(iface=user_choice, filter='port 443', count=SNIFFED_PACKET_COUNT, prn=lambda x: x.summary())

    flow_list = FlowList(user_choice, packets)

    with open(filename, 'w') as output:

        writer = csv.writer(output)
        #outputs the feature name for the headers of the csv file

        for index, flow in enumerate(flow_list.get_flows()):
            if index == 0:
                writer.writerow(flow.get_data().keys())
                writer.writerow(flow.get_data().values())
            else:
                writer.writerow(flow.get_data().values())