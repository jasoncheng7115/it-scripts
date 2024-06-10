
#!/usr/bin/env python3
# Requires installation: pip3 install pyshark graypy tqdm
# Also requires: sudo apt install tshark
#
# Jason Cheng (jason@jason.tools)
# Jason Tools (www.jason.tools)
#
# resend_pakcets_from_pcap
# v1.0
#
import pyshark
import json
import socket

# Configuration variables
graylog_address = '192.168.11.119' 
graylog_port = 32201
host_source = "resend-pcap"
pcap_file = '/root/test.pcap'

def protocol_number_to_name(proto_number):
    protocol_map = {
        '1': 'ICMP',
        '2': 'IGMP',
        '6': 'TCP',
        '8': 'EGP',
        '9': 'IGP',
        '17': 'UDP',
        '47': 'GRE',
        '50': 'ESP',
        '51': 'AH',
        '57': 'SKIP',
        '58': 'IPv6-ICMP',
        '59': 'IPv6-NoNxt',
        '60': 'IPv6-Opts',
        '88': 'EIGRP',
        '89': 'OSPF',
        '94': 'IPIP',
        '97': 'ETHERIP',
        '98': 'ENCAP',
        '103': 'PIM',
        '112': 'VRRP',
        '113': 'PGM',
        '115': 'L2TP',
        '118': 'STP',
        '121': 'SMP',
        '132': 'SCTP',
        '133': 'FC',
        '137': 'MPLS-in-IP',
        '139': 'HIP',
        '140': 'Shim6',
        '142': 'WESP',
        '143': 'ROHC',
        '253': 'Experimentation',
        '254': 'Experimentation-2'
    }
    return protocol_map.get(str(proto_number), proto_number)  # If not found, return the number itself

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
    processed_packets = 0  # Packet counter for displaying progress

    for packet in pyshark.FileCapture(pcap_file, keep_packets=False):
        try:
            timestamp = float(packet.sniff_timestamp)
            protocol = packet.highest_layer
            packet_length = packet.length
            src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, seq_number, flags, ip_protocol = "", "", "", "", "", "", "", "", ""

            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                ip_protocol = protocol_number_to_name(packet.ip.proto)

            if hasattr(packet, 'eth'):
                src_mac = packet.eth.src
                dst_mac = packet.eth.dst

            if 'TCP' in protocol:
                if hasattr(packet, 'tcp'):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    seq_number = packet.tcp.seq
                    flags = get_tcp_flags(packet.tcp.flags)

            elif 'UDP' in protocol:
                if hasattr(packet, 'udp'):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport

            message_content = f"Packet from {src_mac} to {dst_mac} over {protocol}" if not src_ip else f"Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} over {protocol}"

            gelf_message = {
                "version": "1.1",
                "host": host_source,
                "short_message": message_content,
                "timestamp": timestamp,
                "_protocol": protocol,
                "_ip_protocol": ip_protocol,
                "_src_mac": src_mac,
                "_dst_mac": dst_mac,
                "_src_ip": src_ip,
                "_dst_ip": dst_ip,
                "_src_port": src_port,
                "_dst_port": dst_port,
                "_sequence_number": seq_number,
                "_flags": flags,
                "_packet_length": packet_length,
                "_pcap_file": pcap_file
            }
            message_json = json.dumps(gelf_message).encode('utf-8')
            sock.sendto(message_json, (graylog_address, graylog_port))

            processed_packets += 1
            if processed_packets % 100 == 0:
                print(f"Processed {processed_packets} packets")

        except AttributeError:
            continue

    sock.close()
    print("Finished processing all packets.")

def get_tcp_flags(flags):
    flag_descriptions = []
    if int(flags, 16) & 0x01:
        flag_descriptions.append('FIN')
    if int(flags, 16) & 0x02:
        flag_descriptions.append('SYN')
    if int(flags, 16) & 0x04:
        flag_descriptions.append('RST')
    if int(flags, 16) & 0x08:
        flag_descriptions.append('PSH')
    if int(flags, 16) & 0x10:
        flag_descriptions.append('ACK')
    if int(flags, 16) & 0x20:
        flag_descriptions.append('URG')
    return ' '.join(flag_descriptions)

if __name__ == '__main__':
    main()
