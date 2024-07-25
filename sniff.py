import socket
import struct

# convert raw mac address into human readable formate
def get_mac_address(raw_mac):
    raw_adr = map('{:02x}'.format,raw_mac)
    return ':'.join(raw_adr).upper()

get_mac_address(b'\x0d\x5d\x3b\x1a')

#get destination & source mac address and protocol and raw data from packet frame 
# (unpacking them from a packet frame) 
def packet_frame(raw_data):
    dest_mac,srs_mac,protocol = struct.unpack("! 6s 6s",raw_data[:14])

    return get_mac_address(dest_mac), get_mac_address(srs_mac), socket.htons(protocol), raw_data[14:]

# get packets from network using socket library
# creating socket 
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# main loop that'll catch the packets
def main():
    while true:
        raw_data0, address = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = packet_frame(raw_data0)
        print("\n Ethernet Frame: ")
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol {eth_proto}')


