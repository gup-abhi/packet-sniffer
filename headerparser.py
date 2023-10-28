import struct

def get_ip(addr):
    return '.'.join(map(str, addr)) 

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src) 
    target = get_ip(target) 
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data