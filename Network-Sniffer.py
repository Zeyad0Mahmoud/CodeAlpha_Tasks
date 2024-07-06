import socket
import struct
import sys

def format_MAC(data):
    return ":".join(format(b, '02x') for b in data)

def format_IP(data):
    return ".".join(map(str, data))

def eth_header(raw_data):
    dest_MAC, src_MAC, eth_type = struct.unpack("! 6s 6s H", raw_data[:14])
    dest_MAC = format_MAC(dest_MAC)
    src_MAC = format_MAC(src_MAC)
    Protocol = socket.htons(eth_type)
    data = raw_data[14:]
    return dest_MAC, src_MAC, Protocol, data

def ipv4_header(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    src_IP = format_IP(src)
    dest_IP = format_IP(dest)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src_IP, dest_IP, data

def tcp_header(raw_data):
    src_PORT, dest_PORT, sequence, ack, offset_reserved_flags = struct.unpack("! H H L L H", raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4  
    urg_flag = (offset_reserved_flags & 32) >> 5
    ack_flag = (offset_reserved_flags & 16) >> 4
    psh_flag = (offset_reserved_flags & 8) >> 3
    rst_flag = (offset_reserved_flags & 4) >> 2
    syn_flag = (offset_reserved_flags & 2) >> 1
    fin_flag = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_PORT, dest_PORT, sequence, ack, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data

def icmp_header(raw_data):
    Type, code, checksum = struct.unpack("! B B H", raw_data[:4])
    return Type, code, checksum

def udp_header(raw_data):
    src_PORT, dest_PORT, length, checksum = struct.unpack("! H H H H", raw_data[:8])
    return src_PORT, dest_PORT, length, checksum

def create_socket():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError as e:
        print(f"\nPermission error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nError creating socket: {e}")
        sys.exit(1)
    return s

def main():
    s = create_socket()

    while True:
        try:
            raw_data, addr = s.recvfrom(65535)
        except KeyboardInterrupt:
            print("\nTerminating...")
            break
        except Exception as e:
            print(f"\nError receiving data: {e}")
            continue
        
        eth = eth_header(raw_data)
        print("\nEthernet Frame:")
        print(f"\nDestination MAC address: {eth[0]}, Source MAC address: {eth[1]}, Protocol: {eth[2]}")

        if eth[2] == 8:
            ipv4 = ipv4_header(eth[3])
            print("\tIPv4 packet:")
            print(f"\t\tVersion: {ipv4[0]}")
            print(f"\t\tHeader Length: {ipv4[1]}")
            print(f"\t\tTTL: {ipv4[2]}")
            print(f"\t\tProtocol: {ipv4[3]}")
            print(f"\t\tSource IP: {ipv4[4]}")
            print(f"\t\tDestination IP: {ipv4[5]}")
            
            if ipv4[3] == 6:
                tcp = tcp_header(ipv4[6])
                print("\tTCP segment:")
                print(f"\t\tSource PORT: {tcp[0]}")
                print(f"\t\tDestination PORT: {tcp[1]}")
                print(f"\t\tSequence: {tcp[2]}")
                print(f"\t\tAcknowledgment: {tcp[3]}")
                print("\t\tFLAGS:")
                print(f"\t\tURG: {tcp[4]}, ACK: {tcp[5]}, PSH: {tcp[6]}")
                print(f"\t\tRST: {tcp[7]}, SYN: {tcp[8]}, FIN: {tcp[9]}")

                if tcp[0] == 80 or tcp[1] == 80:
                    print("\t\tHTTP protocol")
            elif ipv4[3] == 1:
                icmp = icmp_header(ipv4[6])
                print("\tICMP packet:")
                print(f"\t\tType: {icmp[0]}")
                print(f"\t\tCode: {icmp[1]}")
                print(f"\t\tChecksum: {icmp[2]}")
            elif ipv4[3] == 17:
                udp = udp_header(ipv4[6])
                print("\tUDP segment:")
                print(f"\t\tSource PORT: {udp[0]}")
                print(f"\t\tDestination PORT: {udp[1]}")
                print(f"\t\tLength: {udp[2]}")
                print(f"\t\tChecksum: {udp[3]}")

        

if __name__ == '__main__':
    main()
