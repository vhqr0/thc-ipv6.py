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
parser.add_argument('target')
args = parser.parse_args()
iface = args.iface
do_hbh = args.do_hbh
do_frag = args.do_frag
do_dst = args.do_dst
target = args.target

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

p = sp.Ether(src=mac) / \
    inet6.IPv6(src=ip, dst=target)
if ipexthdrs:
    p /= ipexthdrs
p /= inet6.ICMPv6EchoRequest()

while True:
    sp.sendp(p, verbose=0)
