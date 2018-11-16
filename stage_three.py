from scapy.all import *
from scapy.layers.inet import UDP, IP
from random import randint
import struct
import sys

MINIMUM_PACKET_SIZE = 5


def make_packet(in_packet_id, src_ip, src_port, dest_ip, dest_port, in_data, in_data_len):
    p_ip = IP(src=src_ip, dst=dest_ip, ttl=127)
    p_udp = UDP(sport=src_port, dport=dest_port)
    p_struct = struct.pack("<II", in_packet_id, in_data_len)
    p_struct += in_data[:in_data_len]
    p_data = Raw(p_struct)
    packet = p_ip / p_udp / p_data
    return packet


def create_protocol_data(in_data, src_ip, src_port, dest_ip, dest_port):
    packets = []
    packet_id = 0
    while len(in_data) > 0:
        packet_id += 1
        if len(in_data) < MINIMUM_PACKET_SIZE:
            packet_size = len(in_data)
        else:
            rand_packet_size = randint(MINIMUM_PACKET_SIZE, len(in_data))
            packet_size = rand_packet_size
        packets.append(make_packet(packet_id, src_ip, src_port, dest_ip, dest_port, in_data, packet_size))
        in_data = in_data[packet_size:]
    return packets


def create_conversation(in_data):
    src_ip = "1.1.1.1"
    src_port = 19191
    dest_ip = "2.2.2.2"
    dest_port = 28282
    splitted_text = in_data.splitlines()
    packets = []

    for data in splitted_text:
        packets += create_protocol_data(data.encode("base64"), src_ip, src_port, dest_ip, dest_port)
        tmp = dest_ip
        dest_ip = src_ip
        src_ip = tmp
        tmp = dest_port
        dest_port = src_port
        src_port = tmp
    return packets


def main():
    if len(sys.argv) != 3:
        print "Usage: main.py <pcap_output_file> <text_file>"
        exit(1)

    pcap_path = sys.argv[1]
    with open(sys.argv[2]) as input_file:
        text = input_file.read()

    packets = create_conversation(text)
    wrpcap(pcap_path, packets)


if __name__ == "__main__":
    main()