from scapy.all import *
from scapy.layers.inet import UDP, IP
from random import randint, shuffle
import struct
import sys

MINIMUM_PACKET_SIZE = 5

def make_packet(in_packet_id, in_data, in_data_len):
    p_ip = IP(src="1.1.1.1", dst="2.2.2.2", ttl=127)
    p_udp = UDP(sport=19191, dport=28282)
    p_struct = struct.pack("<II", in_packet_id, in_data_len)
    p_struct += in_data[:in_data_len]
    p_data = Raw(p_struct)
    packet = p_ip / p_udp / p_data
    return packet

def create_protocol_data(in_data):
    packets = []
    packet_id = 0
    while len(in_data) > 0 :
        packet_id += 1
        if len(in_data) < MINIMUM_PACKET_SIZE:
            packet_size = len(in_data)
        else:
            rand_packet_size = randint(MINIMUM_PACKET_SIZE, len(in_data))
            packet_size = rand_packet_size
        packets.append(make_packet(packet_id, in_data, packet_size))
        in_data = in_data[packet_size:]
    return packets


def main():
    if len(sys.argv) != 3:
        print "Usage: main.py <pcap_output_file> <text_file>"
        exit(1)

    pcap_path = sys.argv[1]
    with open(sys.argv[2]) as input_file:
        text = input_file.read()

    packets = create_protocol_data(text.encode("base64"))
    shuffle(packets)
    wrpcap(pcap_path, packets)


if __name__ == "__main__":
    main()