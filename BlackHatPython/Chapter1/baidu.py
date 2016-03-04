#!/usr/bin/python
#coding:utf-8

import socket

target_host = "0x7c00.cn"
target_port = 80

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((target_host, target_port))

client.send("GET / HTTP/1.1 \r\n Host:0x7c00.cn\r\n\r\n ")

response = client.recv(4096)

print response
