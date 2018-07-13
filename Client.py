'''
UDP Field:
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|      Source     |    Destination  |
|       Port      |       Port      |
+--------+--------+--------+--------+
|      Length     |     Checksum    |
+--------+--------+--------+--------+
|
|        data octets ...
+--------------- ...
UDP Pseudo Header
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|           source address          |
+--------+--------+--------+--------+
|        destination address        |
+--------+--------+--------+--------+
|  zero  |protocol|   UDP length    |
+--------+--------+--------+--------+
IP Header
 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|Ver.|IHL|DSCP|ECN|   Total length  |
+--------+--------+--------+--------+
|  Identification |Flags|   Offset  |
+--------+--------+--------+--------+
|   TTL  |Protocol| Header Checksum |
+--------+--------+--------+--------+
|         Source IP address         |
+--------+--------+--------+--------+
|       Destination IP address      |
+--------+--------+--------+--------+
'''

import socket
import struct


def udp_send(data, dest_addr, src_addr=('127.0.0.1', 5000)):
    # Generate pseudo header
    src_ip, dest_ip = ip2int(src_addr[0]), ip2int(dest_addr[0])
    src_ip = struct.pack('!4B', *src_ip)
    dest_ip = struct.pack('!4B', *dest_ip)

    zero = 0

    protocol = socket.IPPROTO_UDP

    # Check the type of data
    if type(data) != bytes:
        data = bytes(data.encode('utf-8'))

    src_port = src_addr[1]
    dest_port = dest_addr[1]

    data_len = len(data)
    udp_length = 8 + len(data)
    checksum = 0
    # pseudo_header = struct.pack('!BBH', zero, protocol, udp_length)
    # pseudo_header = src_ip + dest_ip + pseudo_header
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    checksum = checksum_func(data)
    udp_header = struct.pack('!4H', src_port, dest_port, udp_length, checksum)
    flag = 1
    while flag:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s1:
            s1.sendto(udp_header + data, dest_addr)
            ACK = ""
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                s.bind(('127.0.0.1',2000))
                try:
                    ACK = s.recv(1024)
                    flag = 0
                except s.timeout:
                    print('REQUEST TIMED OUT')

            s.close()
    print(ACK)
    udp_recv(('127.0.0.1', 2000), 2048)
def checksum_func(data):
    print("checksum           ",   str(data))
    checksum = 0
    data_len = len(data)
    if (data_len % 2) == 1:
        data_len += 1
        data += struct.pack('!B', 0)

    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum


def ip2int(ip_addr):
    if ip_addr == 'localhost':
        ip_addr = '127.0.0.1'
    return [int(x) for x in ip_addr.split('.')]
def udp_recv(addr, size):
    zero = 0
    protocol = 17
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(addr)
        i = 0

        f = open("te.html", "w+")
        rnext = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s1:
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            while True:
                data, src_addr = s.recvfrom(size)
                i+=1
                verify = checksum_func(data.split(b'#%')[4])
                data = str(data)[2:-1]
                if ( data != 'error bad request !'   and data != 'error not found !'   ):
                    receive_code = str(data).split('#%')
                    mf = receive_code[2]
                    maindata = receive_code[4]
                    print("rs code"+str(receive_code[1]))
                    print("rnext"  + str(rnext))
                    if(int(verify)== int(receive_code[3]))and( int(receive_code[1]) == int(rnext)) :
                        print("packet",rnext,"received")
                        s1.sendto(bytes("ack"+" "+ str(receive_code[1]), 'utf-8'), ('127.0.0.1', 6100))
                        rnext+=1
                    elif(int(verify)== int(receive_code[3]))and(int(receive_code[1]) < int(rnext)):
                        s1.sendto(bytes("ack" + " " + str(receive_code[1]), 'utf-8'), ('127.0.0.1', 6100))
                    else:
                        print('Checksum Error!Packet is discarded')

                    # print(maindata)
                    f.write(maindata)
                    if(int(mf) == 0):
                        break
        f.close()
def send_DNS(type , server , target ):
    TCP_IP = '127.0.0.1'
    TCP_PORT = 5005
    MESSAGE = bytes(type+"#%"+server+"#%"+target,'utf-8')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TCP_IP, TCP_PORT))
    s.send(MESSAGE)
    receive_DNS()

def receive_DNS():
    TCP_IP = '127.0.0.1'
    TCP_PORT = 3000
    BUFFER_SIZE = 1024  # Normally 1024, but we want fast response
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)

    conn, addr = s.accept()
    while 1:
        data = conn.recv(BUFFER_SIZE)
        if not data: break
    conn.close()


if __name__ == '__main__':
    # send_DNS('CNAME' , '217.215.155.155' , 'mail.google.com')
    udp_send(" GET / http/1.1\r\n\r\n host:www.google.com", ('127.0.0.1', 6000))
