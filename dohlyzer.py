#!/usr/bin/env python

import re
# from enum import Enum, auto

from scapy.all import get_if_list, load_layer
from scapy.sendrecv import AsyncSniffer
from FlowSession import FlowSession

SNIFFED_PACKET_COUNT = 0
load_layer('tls')


def _valid_file(file):
    match = bool(re.match(r"\b(\S)+.csv\b", file) and
                 re.match(r"\b[^/:*#?!=\"<>|.\'@$&`%{}]+.csv\b", file))

    while not match:
        file = input("That is not an acceptable file name, please enter a different file name \n")

        match = bool(re.match(r"\b(\S)+.csv\b", file) and
                     re.match(r"\b[^/:*#?!=\"<>|.\'@$&`%{}]+.csv\b", file))
    return file


def _on_off_line(choice, session):
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
        return AsyncSniffer(offline='dump.pcap', filter='tcp port 443', prn=None, session=session)
    elif choice == 2:
        return _online(session)


def _online(session):
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

    return AsyncSniffer(iface=user_choice, filter='tcp port 443', count=SNIFFED_PACKET_COUNT, prn=None, session=session)


def main():
    # file = input("Please enter a .csv file that you would like to save the results to.\n")
    # file = _valid_file(file)

    while True:
        try:
            choice = 1
            #         choice = int(input("Would you like to use a pcap \
            # file (1) or capture live traffic (2)?\n"))

            break
        except ValueError:
            print("That is not an integer.")

    print(choice)

    sniffer = _on_off_line(choice, FlowSession)
    sniffer.start()
    try:
        sniffer.join()
    except KeyboardInterrupt as e:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == '__main__':
    main()
