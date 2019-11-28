#!/usr/bin/env python

import argparse
import re
import csv
#from enum import Enum, auto

from scapy.all import sniff, get_if_list


#internal imports
from FlowList import FlowList


SNIFFED_PACKET_COUNT = 0

if __name__ == '__main__':
    file = input("Please enter a .csv file that you would like to save the results to.\n")
    match = bool(re.match(r"(\S)+.csv", file) and \
    re.match(r"[^/:*#?!=\"<>|.\'@$&`%{}]+.csv", file))

    while match == False:
        file = input("That is not an acceptable file name,\
        please enter a different file name \n")

        match = bool(re.match(r"(\S)+.csv", file) and \
        re.match(r"[^/:*#?!=\"<>|.\'@$&`%{}]+.csv", file))
    ## Below is the commentted out functionality to choose a different interface
    ## to capture packets
    ## enp0s3 is simply the one that has worked best so far.


    #set count to 0 to get data continuously until this program is interupted
    #in the terminal with ctrl-c
    #replace iface with offline="<filename>"
    choice = int(input("Would you like to use a pcap file (1) or capture live traffic (2)?"))
    print(choice)
    while choice != 1 and choice != 2:
        print("Only an input of the number 1 or the number 2 is accepted")
        choice = int(input("Would you like to use a pcap file (1) or capture live traffic (2)?"))

    if choice == 1:
        packets = sniff(offline = 'test.pcap', filter='tcp port 443', prn=lambda x: x.summary())
        user_choice = 'enp0s3'
    elif choice == 2:
        options = get_if_list()

        print("Please choose which interface you wish to analyze:")
        for i, interface in enumerate(options):
            print("({}) {}".format(i + 1, interface))

        user_entry = int(input()) - 1

        user_choice = options[user_entry]

        print("Capturing packets from `{}` interface...".format(user_choice))
        
        packets = sniff(iface = user_choice, filter = 'port 443', \
            count = SNIFFED_PACKET_COUNT, prn = lambda x: x.summary())

    flow_list = FlowList(user_choice, packets)

    with open(file, 'w') as output:

        writer = csv.writer(output)
        #outputs the feature name for the headers of the csv file

        for index, flow in enumerate(flow_list.get_flows()):
            if index == 0:
                writer.writerow(flow.get_data().keys())
                writer.writerow(flow.get_data().values())
            else:
                writer.writerow(flow.get_data().values())
