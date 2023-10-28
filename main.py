import socket
import textwrap
from packetparser import ethernet_head as ethernet
from tcppackets import tcp_head
from networking.http import HTTP
from headerparser import ipv4_head

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    # creating an INET raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,  socket.ntohs(3))

    # Infinite loop to receive data from the socket
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Prototype: {}'.format(eth[0], eth[1], eth[2]))
        if eth[2] == 8:
            ipv4 = ipv4_head(eth[3])
            print( '\t - ' + 'IPv4 Packet:')             
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4[1], ipv4[2], ipv4[3]))             
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[4], ipv4[5], ipv4[6])) 

            if ipv4[4] == 6:      
                tcp = tcp_head(ipv4[7])     
                print(TAB_1 + 'TCP Segment:')     
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))     
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))     
                print(TAB_2 + 'Flags:')     
                print(TAB_3 + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))     
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))      
                if len(tcp[10]) > 0:          
                    # HTTP         
                    if tcp[0] == 80 or tcp[1] == 80:              
                        print(TAB_2 + 'HTTP Data:')                  
                        try:                     
                            http = HTTP(tcp[10])                     
                            http_info = str(http[10]).split('\n')                     
                            for line in http_info:                        
                                print(DATA_TAB_3 + str(line))                  
                        except:                        
                            print(format_multi_line(DATA_TAB_3, tcp[10]))                  
                    else:                       
                        print(TAB_2 + 'TCP Data:')                       
                        print(format_multi_line(DATA_TAB_3, tcp[10])) 


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



main()
