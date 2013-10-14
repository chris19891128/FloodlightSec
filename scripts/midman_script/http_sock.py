#! /usr/bin/python

import socket
import sys


def forwardRequest(listen_port, dst_addr):
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    recv_sock.bind(('', listen_port))
    recv_sock.listen(5)

    while True:
        client, addr = recv_sock.accept()
        req = client.recv(4096)
        
        try:
            send_sock.connect((dst_addr, listen_port))
        except socket.error:
            print "error connecting to dst_addr", dst_addr 
            client.close()
            recv_sock.close()
            break
        send_sock.send(req)

        data = send_sock.recv(8192)
            
        client.send(data.replace('my', 'HACKER\'s'))
        client.close()
        
        
        

if __name__ == '__main__':
    if len(sys.argv) > 2:
        forwardRequest(int(sys.argv[1]), sys.argv[2])
    else:
        print "usage: python http_sock.py port ip_addr"
