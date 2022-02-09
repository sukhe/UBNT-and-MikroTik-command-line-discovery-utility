# UBNT and Mikrotik command line discovery utility
Command line utility for Ubiquiti (UBNT) Device Discovery and MikroTik Neighbor Discovery Protocol (MNDP)

## Purpose of the program

This utility is designed to search in the local network devices manufactured by UBNT and MikroTik  - wireless access points, routers, switches.

Unlike manufacturers' utilities, this one does not have a graphical interface. That allows you to use it in scripts, run it from cron, etc.

The search is performed both using proprietary protocols and CDP and LLDP protocols. Therefore, devices from other manufacturers may be present in the results.

You can explicitly specify which protocols to use. Or you can specify the `u` or `m` options to use the same protocol set as Ubiquity and Microtik.

Because different protocols have different data fields - you can save the results for each protocol in a separate file.

The program was tested on Python 3.7 and 3.8 on Debian 10 and FreeBSD 13.

## Using the discovery.py

First, you need to specify where the program receives data from. 

There are two possible options:
1) capturing packets from the network (specify the interface name)
2) parsing a file with previously captured packets (specify the file name)

Packet capturing can be active or passive (silence). In passive mode, it simply listens to the network and captures suitable packets.

In active mode, discovery packets of a special format are sent to the network, to which UBNT or Mikrotik devices respond.

It is worth noting that only those devices that have the corresponding option enabled in the settings will respond.

A discovery packet can have a source address and port specified.

Since packet loss is possible in the transmission medium, several discovery packets can be sent (the number of packets and the time between them is configurable).

Time for waiting responces is also assigned.

Captured packets can be saved for later parsing in a pcap file.

The results of packet parsing are output to a text file and to standard output.

Possible output formats - txt, json, csv, tree (tree output with grouping wi-fi clients by access points).



usage: discovery.py [-h] (-r READ | -i INTERFACE) [-a ADDRESS] [-p PORT] [-P PROTOCOLS [PROTOCOLS ...]] [-m] [-u] [-S] [-s] [-t TIMEOUT] [-c COUNT] [-d DELAY]
                    [-w WRITE] [-f FILE_NAME] [-y {json,csv,txt,tree}] [--file-options FILE_OPTIONS] [-o {json,csv,txt,tree}] [--output-options OUTPUT_OPTIONS]
                    [-q]

optional arguments:
  -h, --help            show this help message and exit
  -r READ, --read READ  Load data from previously stored .pcap file
  -i INTERFACE, --interface INTERFACE
                        Source interface for discovery request
  -a ADDRESS, --address ADDRESS
                        Source address for MNDP discovery request. If not specified, requests will be sent to all addresses assigned to the interface. (default
                        - not specified)
  -p PORT, --port PORT  Source port for UBNT discovery request (default - 33333)
  -P PROTOCOLS [PROTOCOLS ...], --protocols PROTOCOLS [PROTOCOLS ...]
                        Protocols, used to discovery (default - cdp mndp lldp ubnt)
  -m, --mikrotik        Emulate MikroTik Neighbor Discovery (default - not specified)
  -u, --ubnt            Emulate UBNT discovery (default - not specified)
  -S, --separate-files  Use a separate result files for each protocol (default - don't use, with csv type file - always used)
  -s, --silence         Don't send discovery packet. Use only passive capturing.
  -t TIMEOUT, --timeout TIMEOUT
                        How long wait responses, in seconds (default - 20)
  -c COUNT, --count COUNT
                        How many discovery requests to send (default - 3)
  -d DELAY, --delay DELAY
                        Delay between discovery requests, seconds (default - 2)
  -w WRITE, --write WRITE
                        Save received responses to .pcap file
  -f FILE_NAME, --file-name FILE_NAME
                        Filename for store result
  -y {json,csv,txt,tree}, --file-type {json,csv,txt,tree}
                        Type for storing results in file: "json", "csv", "txt", "tree" (default - "json")
  --file-options FILE_OPTIONS
                        For "json" files - indent (default - 4), for "csv" - delimiter (default - ",")
  -o {json,csv,txt,tree}, --output-type {json,csv,txt,tree}
                        Format for output results to stdout: "json", "csv", "txt", "tree" (default - "txt")
  --output-options OUTPUT_OPTIONS
                        For "json" format - indent (default - 4), for "csv" - delimiter (default - ",")
  -q, --quiet           Disable output to stdout (default - not specified)
