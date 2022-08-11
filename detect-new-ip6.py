import argparse
import sys
import os
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('-s', '--script')
args = parser.parse_args()
iface = args.iface
script = args.script

if iface:
    sp.conf.iface = iface


def prn(pkt):
    tgt = pkt[inet6.ICMPv6ND_NS].tgt
    print(f'Detect DAD to {tgt}')

    if script:
        if os.fork() == 0:
            os.system(f'{script} {tgt}')
            sys.exit(0)


filterstr = 'icmp6[icmp6type]==icmp6-neighborsolicit and ip6 src ::'

sp.sniff(filter=filterstr, prn=prn, quiet=True)
