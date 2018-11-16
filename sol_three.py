from scapy.all import *
import struct
import sys


def parse_packet(packet):
    data = str(packet[IP][UDP].payload)
    packet_id = struct.unpack("<I", data[:4])[0]
    packet_data = data[8:]
    return {"id": packet_id, "data" : packet_data}


def parse_side(packets, src_ip):
    side_1_packet = [p for p in packets if p[IP].src == src_ip]
    parsed_packets = [parse_packet(p) for p in side_1_packet]
    data = ""
    for packet in parsed_packets:
        if packet["id"] == 1:
            if len(data) != 0:
                print data.decode("base64")
            data = ""
        data += packet["data"]
    print data.decode("base64")

def main():
    packets = rdpcap(sys.argv[1])
    parse_side(packets, "1.1.1.1")
    print "-------------------------------"
    parse_side(packets, "2.2.2.2")


if __name__ == "__main__":
    main()