import struct

def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])     
    offset = (offset_reserved_flags >> 12) * 4     
    flag_urg = (offset_reserved_flags & 32) >> 5     
    flag_ack = (offset_reserved_flags & 16) >> 4     
    flag_psh = (offset_reserved_flags & 8) >> 3     
    flag_rst = (offset_reserved_flags & 4) >> 2     
    flag_syn = (offset_reserved_flags & 2) >> 1     
    flag_fin = offset_reserved_flags & 1     
    data = raw_data[offset:]     
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data 