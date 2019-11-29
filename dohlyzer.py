#!/usr/bin/env python

import argparse
import re
import csv
#from enum import Enum, auto

from scapy.all import sniff, get_if_list


#internal imports
from FlowList import FlowList


SNIFFED_PACKET_COUNT = 0

def _valid_file(file) -> str:
    match = bool(re.match(r"\b(\S)+.csv\b", file) and \
    re.match(r"\b[^/:*#?!=\"<>|.\'@$&`%{}]+.csv\b", file))

    while match == False:
        file = input("That is not an acceptable file name,\
please enter a different file name \n")

        match = bool(re.match(r"\b(\S)+.csv\b", file) and \
        re.match(r"\b[^/:*#?!=\"<>|.\'@$&`%{}]+.csv\b", file))
    return file

def _on_off_line(choice):
    while choice != 1 and choice != 2:
        print("Only an input of the number 1 or the number 2 is accepted")
        while True:
            try:
                choice = input("Would you like to use a pcap file (1) or capture live traffic (2)?\n")
                choice = int(choice)
                break
            except ValueError:
                print("The input must be integers only.")


    if choice == 1:
        packets = sniff(offline = 'test.pcap', filter='tcp port 443', prn=lambda x: x.summary())
        user_choice = 'enp0s3'
    elif choice == 2:
        packets, user_choice  = _online()

    return packets, user_choice

def _online():
    options = get_if_list()
    print("Please choose which interface you wish to analyze: ")
    for i, interface in enumerate(options):
        print("({}) {}".format(i + 1, interface))
    while True:
        try:
            user_entry = int(input()) - 1
            user_choice = options[user_entry]
            break
        except ValueError:
            print("Please enter a number only")
        except IndexError:
            print("Please enter a number that is contained within the list only.")       
         
    print("Capturing packets from `{}` interface...".format(user_choice)) 

    packets = sniff(iface = user_choice, filter = 'port 443', \
    count = SNIFFED_PACKET_COUNT, prn = lambda x: x.summary())

    return packets, user_choice


if __name__ == '__main__':
    file = input("Please enter a .csv file that you would like to save the results to.\n")
    file = _valid_file(file)

    while True:
        try:
            choice = int(input("Would you like to use a pcap \
file (1) or capture live traffic (2)?\n"))
            
            break
        except ValueError:
            print("That is not an integer.")

    print(choice)
    packets, user_choice = _on_off_line(choice)

    output = open(file, 'w'):
    writer = csv.writer(output)


    FlowList(user_choice, packets, output)

        # for index, flow in enumerate(flow_list.get_flows()):
        #     if index == 0:
        #         writer.writerow(flow.get_data().keys())
        #         writer.writerow(flow.get_data().values())
        #     else:
        #         writer.writerow(flow.get_data().values())