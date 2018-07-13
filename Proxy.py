import  socket,select
import sys
from _thread import  *

import struct

listening_port_udp = 6000
proxy_address = '127.0.0.1'
max_connection = 2
buffer_size = 4096
client_ip = '127.0.0.1'
client_port = 2000


def send_back(data):
    print("send data back to client")
    receive_code = str(data).split(' ')[1]
    if int(receive_code) == 200:
        print(" 200 is ok :)")
        # print("received data:", data)
        # fragment it
        # connection.send(data)
        # connection.close()
        segment_data_size = 300
        MF = 0
        segment_number = 0
        base = 0
        next_seqnum = 0
        window = 5
        if len(data)<=segment_data_size :
            checksum = checksum_func(data)
            msg = "#" + str(segment_number) + "#" + str(MF) +"#"+ str(checksum)+"#"+ str(data)
            message = bytes(msg,'utf-8')
            flag = 1
            while flag:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s1:
                    s1.sendto(message, (client_ip, client_port))
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(1.0)
                        s.bind(('127.0.0.1', 6100))
                        try:
                            s.recv(1024)
                            flag = 0
                        except socket.timeout:
                            print('REQUEST TIMED OUT')

                    s.close()
        else:
            packetnumber = int(len(data) / segment_data_size) + 1
            s = socket.socket(socket.AF_INET,  # Internet
                              socket.SOCK_DGRAM)  # UDP
            j=0
            print("packet num" ,packetnumber)
            while base < packetnumber :
                while (next_seqnum < base + window ) and  (j < packetnumber):

                    print("j :", j)
                    segment_number = j
                    print("packet number",segment_number)

                    MF = 1
                    if j == packetnumber - 1:
                        # global MF
                        MF = 0

                    start = j  * segment_data_size
                    end = (j+1) * segment_data_size
                    if end > len(data):
                        # global end
                        end = len(data)
                    checksum = checksum_func(bytes(data[start:end],"utf-8"))
                    print("checksum",bytes(data[start:end],"utf-8"))
                    print("checksum", checksum)
                    msg = "#" + str(segment_number) + "#" + str(MF) + "#"+str(checksum)+"#" + str(data[start:end])
                    message = bytes(msg, 'utf-8')

                    s.sendto(message, (client_ip,client_port ))
                    next_seqnum += 1
                    j += 1
                    if (base== next_seqnum):
                        s.settimeout(5.0)

                flag = 1

                while(flag):
                    if socket.timeout:
                        # flag = 0
                        print("time out")
                        s.settimeout(5.0)
                        print("base :" ,base)
                        print("net seqnum :",next_seqnum)
                        for k in range(base,next_seqnum):
                            print("resend     ",k)
                            segment_number = k

                            MF = 1
                            if k == packetnumber - 1:
                                # global MF
                                MF = 0

                            start = k * segment_data_size
                            end = (k + 1) * segment_data_size
                            if end > len(data):
                                # global end
                                end = len(data)
                            checksum = checksum_func(bytes(data[start:end], "utf-8"))
                            print("checksum",bytes(data[start:end],"utf-8"))
                            print("checksum", checksum)
                            msg = "#" + str(segment_number) + "#" + str(MF) + "#" + str(checksum) + "#" + str(data[start:end])
                            message = bytes(msg, 'utf-8')

                            s.sendto(message, (client_ip, client_port))

                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s1:
                        s1.bind(('127.0.0.1', 6100))
                        s1.settimeout(7.0)
                        try:
                            print("ahhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")
                            ack = s1.recvfrom(1024)
                            print(str(ack),"ackkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")
                            number = str(ack).split(' ')[1]
                            base = int(number[:-2]) + 1
                            if base != next_seqnum :
                                s.settimeout(1.0)
                            flag = 0
                        except socket.timeout:
                            print('REQUEST TIMED OUT')
                        s1.close()
                    print("end of while")





            s.close()


    elif  int(receive_code) == 404:
        print("404 not found")
        s = socket.socket(socket.AF_INET,  # Internet
                          socket.SOCK_DGRAM)  # UDP

        s.sendto(bytes('error not found !', 'utf_8'), (client_ip, client_port))
        s.close()


    elif  int(receive_code) == 400:
        print("400 bad request")
        s = socket.socket(socket.AF_INET,  # Internet
                          socket.SOCK_DGRAM)  # UDP

        s.sendto(bytes('error bad request !', 'utf_8'), (client_ip, client_port))
        s.close()

    elif int(receive_code) == 301 or  int(receive_code) == 302:
        print("server is  moved")
        lines = str(data).split('\\r\\n')
        for l in lines:
            if 'Location:' in l:
                print(l)
                location = l.split('//')[1]
                location =  location.split('\\')[0]
                print(location)


        # now we must send request to server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((location, 80))
        # in this project all is this
        s.send(bytes('GET / HTTP/1.0\r\n\r\n', 'utf-8'))
        all_new_data = []
        while 1 :
            new_data = s.recv(buffer_size)
            if len(new_data) >0 :
                all_new_data.append(new_data)
            else:
                break

        send_back(''.join(all_new_data))



def receive_from_server(connection, data):

    server_port = 80
    s = str(data).split(':')
    # host_line = str(data).split('\n')[2]
    # server_name = host_line.split(':')[1]

    server_name = s[1][:-1]
#now we must send request to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_name, server_port))
    #in this project all is this
    s.send(bytes('GET / HTTP/1.0\r\n\r\n', 'utf-8'))
    all_new_data = []
    while 1:
        new_data = s.recv(buffer_size)
        if len(new_data) > 0:
            # print(new_data)
            all_new_data.append(str(new_data))
            # print(str(new_data))
        else:
            break

    send_back(''.join(all_new_data))

def checksum_func(data):
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

#---------------------------------------------------------------------------------------------------------------------
#this is for receiving data from client in udp
try:
    server  = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    server.bind(('127.0.0.1' ,listening_port_udp))

    # server.listen()
    print("initialize is done proxy is listening")
except Exception as e :
    print(e)
    print("unable to initialize ")
    sys.exit(2)


while 1:
    try :
        # connection ,address = server.accept()
        # print(address)
        #???????????????????????????????????????????????i thick address is its port

        data , addr = server.recvfrom(buffer_size)
        d = data[0:8]
        r = data[8:]
        udp_header = struct.unpack('!4H',d)
        print(udp_header)
        verify = checksum_func(r)
        if verify == udp_header[3]:
            server.sendto(bytes("ack",'utf-8'),('127.0.0.1',2000))
        else:
            print('Checksum Error!Packet is discarded')

        # client_ip = addr[0]
        # client_ip = addr[1]
        #bayad betonim ip and port client ro berizim to client_ip and client_port global
        print("proxy   ",data)
        if data is 0 :
            break
        else:
            start_new_thread(receive_from_server, (server, data))

    except KeyboardInterrupt as e:
        server.close()
        sys.exit(1)

server.close()
