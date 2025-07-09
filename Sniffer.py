import socket 
import struct
import textwrap

#Frames the info like this:
#ethernet
    #IPv4 (IP  packet)
        #"data"
        #TCP
            #"data"

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


#listens to packets come in and loops through function indefinitely
def main():

    #create socket (endpoint for communication between 2 programs like the internet and your router that is connected through a network ie abstraction)
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    
    # Bind to your network interface
    conn.bind(("0.0.0.0", 0))  # Listen on all interfaces
    
    # Include IP headers in captured packets
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        #takes socket created above and recieve all the info and store in variables raw_data and addr (65536 is the largest packet size)
        raw_data, addr = conn.recvfrom(65536)

        #takes data flowing from the internet (raw_data), passing it into ethernet_frame to extract the info we want and storing in variables
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        #prints the dest, source, and protocol of a website on your system
        print('\nEthernet Frame:')
        print( TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto,)) 
    
        #protocol 8 for ethernet cable IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            
            #print header info for IPv4 packet
            print(TAB_1 + 'IPv4 Packet')
            print(TAB_2 + 'Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            #protocol 1 for ICMP
            if  proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data) #call the icmp_packet function on the data recived in the ethernet cable
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(DATA_TAB_3, data)

            #protocol 6 for TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data) #call the tcp_packet function on the data recived in the ethernet cable
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(DATA_TAB_3,data)
            
            #protocol 17 for UDP
            elif proto == 17:
                src_port, dest_port, length, data =  udp_segment(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data: ')
                print(DATA_TAB_3,data)

            else:
                print(TAB_1 + 'Data: ')
                print(DATA_TAB_2, data)
        
        else: 
            print(TAB_1 + 'Data: ')
            print(DATA_TAB_1, data)

#unpack ethernet frame function : takes in packet information and figures out what info the 1 and 0 are trying to convey
def ethernet_frame(data):

    #get destination and source address, prototype by passing data into unpack function by specifying how many bytes for each variable (6s = 6 bytes)
    dest_mac, src_mac, proto = struct.unpack('!6s 6s H', data[:14])

    #return the dest and scr address, prototype, and payload data(14:) in the correct format
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#return properly formated MAC address( ie AA:BB:CC:)
def get_mac_addr(bytes_addr):

    #'mac' passes in an iterable and a function and loops through data and applies that function to the data iterably
    bytes_str = map('{:02x}'.format, bytes_addr)  #formats byte address to the 2 decimal points in a string 

    #seperates "chuncks" by ':' and makes all letters uppercase and returns value = mac address
    return ':.'.join(bytes_str).upper()

#unpack IPV4 packet
def ipv4_packet(data):

    #gives us the first byte of that IP header (version and header length combined in one byte)
    version_header_length = data[0]

    #extract only version number(since first byte contains both version and header length) using bitwise operations
    version = version_header_length >> 4

    #extract the header length so we know where data in the IP address begins
    #"&" isolates the specific bit (15 in this case)
    header_length = (version_header_length & 15) * 4
    
    #"time to live", protocol, source and target addr from the start of the Ip header to the 20th bit
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    #the header + data after the header length
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#formatting IP address (ie. 111.2.3.4 etc)
def ipv4(addr):

#take all the chunks of numbers, seperate them by a period, then join them as a string
    return '.'.join(map(str, addr))

#3 main types of packets (ICMP, TCP, UDP)

#unpacking ICMP type packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    #return the header info + the data starting from the 4th byte to the end
    return icmp_type, code, checksum, data[4:]

#unpack TCP segment (because it is in the transport layer where data bits are called segments)
#TCP header + IP header = IP packet
def  tcp_segment(data):

    #offset_reserve_flags = 16 bits split into offset + reserved + TCP flags
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H ', data[:14]) 
    offset = (offset_reserved_flags >> 12) * 4

    #TCP three - way handshake, ie 6 control flags in the last 6 bits of the offset_reserved_flags (handles connection)
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1 

    #return the TCP  header variables, then all the actual data of the packet after the offset
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#UDP unpacking
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


    
main()
