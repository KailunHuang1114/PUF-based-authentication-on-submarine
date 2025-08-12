import socket
import random
import string
import hashlib
import sys


HOST = "127.0.0.1"  
PORT = 5000


def start_client():
    	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	client_socket.connect((HOST, PORT))
	V_i = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
	C_Vi = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
	R_Vi = hashlib.sha256(C_Vi.encode('utf-8')).hexdigest()
	registration_data = "{}|{}|{}".format(V_i, C_Vi, R_Vi)
	client_socket.sendall(registration_data)
	server_reply = client_socket.recv(1024)
	print "[Server]", server_reply
	private_key_msg = client_socket.recv(1024)
	if private_key_msg:
    		print "[Private Key Received]", private_key_msg


    	print "[*] Connected to server"

    	try:
        	while True:
            		msg = raw_input("Enter message (q to quit): ")
            		if msg.lower() == "q":
                		break
            		client_socket.sendall(msg)
            		data = client_socket.recv(1024)
            		print "[Server reply]", data
    	finally:
        	client_socket.close()

if __name__ == "__main__":
    	start_client()
