import socket
import struct
import textwrap

TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "


# unpack ethernet frame
def ethernet_frame(data):
    # src, dest address are 6 bytes each and 2 bytes for type of packet i.e. ipv4/arp/rarp/ipv6 etc.
    # ! 6s 6s H is just a form of representation - 6bytes, 6bytes, H - small unsigned int.
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]
    # data[14:] is the actual payload. We dont know how big

# return properly formatted mac address i.e. AA:BB:CC:DD:EE:FF
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# unpacks ipv4 packet
def ipv4_packet(data):
    # version and header length together is 1 byte
    # but both together isn't usefull
    version_header_length = data[0]
    # to extract the first 4 bits, right shift
    version = version_header_length >> 4
    header_len = (version_header_length  & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]

# Returns properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# unpacks ICMP protocol
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# unpacks tcp segment - 95% of the times the packet will be tcp
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# unpacks udp segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])




# MAIN CODE
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print('Ethernet frame:', )
    print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


    # 8 for ipv4
    if eth_proto == 8:
        (version, header_len, ttl, proto, src, target, data) = ipv4_packet(data)
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_len, ttl))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

        # ICMP
        if proto == 1:
            icmp_type, code, checksum, data = icmp_packet(data)
            print(TAB_1 + 'ICMP Packet:')
            print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum ))
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))


        # TCP
        elif proto == 6:
            src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
            print(TAB_1 + 'TCP segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
            print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, ack))
            print(TAB_2 + 'Flags:')
            print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))


        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)
            print(TAB_1 + 'UDP segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))

        # Other
        else:
            print(TAB_1 + 'Other IPv4 Packet:')
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))

    # ARP Pcket 1544?
    elif eth_proto == 1544:
        print(TAB_1 + '1544 ARP packet')


    # ARP packet
    #elif eth_proto == 2054:
    #    print(TAB_1 + 'ARP packet:')


    # RARP packet
    #elif eth_proto == 32821:
    #    print(TAB_1 + 'RARP Packet:')


