# -*- coding: utf-8 -*- 
'''

This is for functions potentially used by all modules

'''

import argparse
import os
import random
import re
import string
import sys
import time

def cli_parser():
    # Command line argument parser
    parser = argparse.ArgumentParser(
        add_help=False,
        description='''This tool is used to assess egress filters
        protecting a network.
        Currently only supports FTP, DNS, HTTPS and ICMP clients.''')
    parser.add_argument(
        '-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)

    protocols = parser.add_argument_group('Client Protocol Options')
    protocols.add_argument(
        "--client", default=None, metavar="[http]",
        help="Extract data over the specified protocol.")
    protocols.add_argument(
        "--client-port", default=None, metavar="34567", type=int,
        help="Port to connect over if using non-standard port.")
    protocols.add_argument("--ip", metavar="192.168.1.2", default=None,
                           help="IP to extract data to.")

    ftp_options = parser.add_argument_group('FTP Options')
    ftp_options.add_argument(
        "--username", metavar="testuser", default=None,
        help="Username for FTP server authentication.")
    ftp_options.add_argument(
        "--password", metavar="pass123", default=None,
        help="Password for FTP server authentication.")

    data_content = parser.add_argument_group('Data Content Options')
    data_content.add_argument(
        "--file", default=None, metavar='/root/test.jpg',
        help="Path to file for exfiltration.")

    args = parser.parse_args()

    if args.h:
        parser.print_help()
        sys.exit()

    if ((args.client == "ftp" or args.client == "sftp")) and (
            args.username is None or args.password is None):
        print "[*] Error: FTP or SFTP connections require \
            a username and password!".replace('    ', '')
        print "[*] Error: Please re-run and provide the required info!"
        sys.exit(1)

    if args.client and args.ip is None:
        print "[*] Error: You said to act like a client, but provided no ip"
        print "[*] Error: to connect to.  Please re-run with required info!"
        sys.exit(1)

    if (args.client is not None) and (
            args.file is None):
        print "[*] Error: You need specify which file to send!".replace('    ', '')
        print "[*] Error: to connect to.  Please re-run with required info!"
        sys.exit(1)

    return args

def received_file(filename):
    print("[+] {} - Received File - {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), filename))


def title_screen():
    os.system('clear')
    print "#" * 80
    print "#" + " " * 32 + "Egress-Assess-Lite" + " " * 33 + "#"
    print "#" * 80 + "\n"
    return

def validate_ip(val_ip):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    ip_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
    if ip_re.match(val_ip):
        quads = (int(q) for q in val_ip.split('.'))
        for q in quads:
            if q > 255:
                return False
        return True
    return False

def class_info():
    class_image = '''Exfiltration Completed Successfully'''
    print(class_image)
