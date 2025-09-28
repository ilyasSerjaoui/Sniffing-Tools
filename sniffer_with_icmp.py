import socket
import os
import struct
from ctypes import *
host = "0.0.0.0"

# our IP header

class IP(Structure):
    __fields__ = [
        ("ihl",		c_ubyte, 4),
        ("version",	c_ubyte, 4),
        ("tos",		c_ubyte),
        ("len",		c_ushort),
        ("id",		c_ushort),
        ("offset",	c_ushort),
        ("ttl",		c_ubyte),
        ("protocol_num",c_ubyte),
        ("sum",		c_ushort),
        ("src",		c_ulong),
        ("dst",		c_ulong)
    ]
    
    def __new__(self,socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
        
    def __init__(self,socket_buffer=None):
    
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP",6:"TCP",17:"UDP"}
        
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
        
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):

    __fields__ = [
        ("type",	c_ubyte),
        ("code",	c_ubyte),
        ("checksum",	c_ushort),
        ("unused",	c_ushort),
        ("next_hop_mtu",c_ushort)
    ]
    
    def __new__(self,socket_buffer):
        return self.from_buffer_copy(socket_buffer)
        
    def __init__(self, socket_buffer):
        pass
        
# this should look familiar from the previous example
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]

        if os.name != "nt":
            # skip Ethernet header on Linux (14 bytes)
            ip_header = IP(raw_buffer[14:34])
        else:
            ip_header = IP(raw_buffer[0:20])

        print("Protocol: %s %s -> %s" % (ip_header.protocol,
                                         ip_header.src_address,
                                         ip_header.dst_address))

        # If it's ICMP, parse further
        if ip_header.protocol == "ICMP":
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            icmp_header = ICMP(buf)
            print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) 
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
