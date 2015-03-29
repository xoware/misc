#!/usr/bin/python2

import os
import socket

print "Content-type: text/html\r\n\r\n";

# send to 
UDP_IP = os.environ['REMOTE_ADDR']
MESSAGE = "HELLO"

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

sent_500 = sock.sendto(MESSAGE, (UDP_IP, 500))
sent_4500 = sock.sendto(MESSAGE, (UDP_IP, 4500))

print "{ \"sent500\" : %d, \"sent4500\" : %d }\n" % (sent_500, sent_4500);

#retry 1
sent_500 = sock.sendto(MESSAGE, (UDP_IP, 500))
sent_4500 = sock.sendto(MESSAGE, (UDP_IP, 4500))

#retry 2
sent_500 = sock.sendto(MESSAGE, (UDP_IP, 500))
sent_4500 = sock.sendto(MESSAGE, (UDP_IP, 4500))
