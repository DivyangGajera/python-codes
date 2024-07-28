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
    while True:
        raw_data, address = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, eth_frame_data = packet_frame(raw_data)
        print("\nEthernet Frame: ")
        print(f'\tDestination MAC Address: {dest_mac}, Source MAC Address: {src_mac}, Protocol: {eth_proto}')

        # protool = 8 meaens it's an IPv4 packet
        if eth_proto == 8:
            version, header_length, ttl, proto, src_address, dest_address, ipv4_data = ipv4_packets_unpacking(eth_frame_data)
            print('\tIPv4 Packet:')
            print(f'''\t\t Version: {version}, Header Length: {header_length}
                  \t\t TTL:{ttl}, Protocol: {proto}
                  \t\t Source IPv4 Adress: {src_address}, Destination IPv4 Address: {dest_address}''')
            
            # protocolo = 1 or 2 means it's an ICMP packet
            if proto == 1 or proto == 2:
                icmp_type, code, check_sum, icmp_data = icmp_packets_unpacking(ipv4_data)
                print('\tICMP Packet:')
                print(f'''\t\t Type: {icmp_type}, Code: {code}, Check Sum:{check_sum},
                      \t\tdata: 
                      {icmp_data}\n''')

            # protocolo = 6 means it's a TCP packet
            elif proto == 6:
                tdp_src_port, tdp_dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, = tcp_packets_unpacking(ipv4_data)
                print('\tTDP Packet:')
                print(f'''\t\t Source Port No.: {tdp_src_port}, Destionation Port No.: {tdp_dest_port},
                       \t\t Sequence:{sequence}, Acknowledgement: {acknowledgement}, 
                       \t\t Flags:
                       \t\t\t URG : {flag_urg}, ACK:{flag_ack},
                       \t\t\t PSH : {flag_psh}, RST:{flag_rst},
                       \t\t\t SYN : {flag_syn}, FIN:{flag_fin},
                      \t\tdata: 
                      {udp_data}\n''')

            # protocolo = 17 means it's an UDP packet
            elif proto == 17:
                udp_src_port, udp_dest_port, size, udp_data = udp_packets_unpacking(ipv4_data)
                print('\tUDP Packet:')
                print(f'''\t\t Source Port No.: {udp_src_port}, Destionation Port No.: {udp_dest_port}, Size:{size},
                      \t\tdata: 
                      {udp_data}\n''')
            else:
                print(f'''\t\tdata: 
                      {udp_data}\n''')


# unpacking the IPv4 Packets
def ipv4_packets_unpacking(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4 
    ttl, proto, src_adr, dest_adr = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    return version, header_length, ttl, proto, formate_to_ipv4(src_adr), formate_to_ipv4(dest_adr),  raw_data[header_length:]

# formating ipv4 adress to human readable form
def formate_to_ipv4(crudeAddress):
    return '.'.join(map(str,crudeAddress))

# ICMP packets unpacking
def icmp_packets_unpacking(raw_data):
    icmp_type, code, check_sum = struct.unpack('! B B H',raw_data[:4])
    return type, code, check_sum, raw_data[4:]

# TCP packets unpacking
def tcp_packets_unpacking(raw_data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4 
    flag_urg = (offset_reserved_flags & 32) >> 5  
    flag_ack = (offset_reserved_flags & 16) >> 4  
    flag_psh = (offset_reserved_flags & 8) >> 3  
    flag_rst = (offset_reserved_flags & 4) >> 2  
    flag_syn = (offset_reserved_flags & 2) >> 1  
    flag_fin = offset_reserved_flags & 1  
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, raw_data[offset:]

# UDP packets unpacking
def udp_packets_unpacking(raw_data):
    src_port, dest_port, size = struct.unpack("! H H 2x H",raw_data[:8])
    return src_port, dest_port, size, raw_data[8:]