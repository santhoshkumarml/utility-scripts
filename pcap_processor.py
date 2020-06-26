import sys

from scapy.layers.http import HTTP
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


# tcpdump -A -vvvs 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -w ~/sample.pcap

def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue

        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        packet = ether_pkt[IP]

        if packet.proto != 6:
            # Ignore non-TCP packet or if its is not http
            continue
        tcp_packet = packet[TCP]

        if isinstance(tcp_packet.payload, HTTP):
            http_packet = tcp_packet[HTTP]
            summary = repr(http_packet)
            print(f'{packet.src}  {packet.dst}  {summary}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Correct usage : python pcap_processor.py ${pcap file path}")
    process_pcap(sys.argv[1])

