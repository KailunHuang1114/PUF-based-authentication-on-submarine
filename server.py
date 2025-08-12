import socket
import threading
import os

registered_auv = {}

HOST = "0.0.0.0"  
PORT = 5000

def handle_client(conn, addr):
    	print "[+] Connected by {}".format(addr)
    	try:
        	while True:
            		data = conn.recv(1024)
            		if not data:
                		break
			parts = data.split('|')
			if len(parts) == 3:
    				V_i, C_Vi, R_Vi = parts
    				print "[Registration] V_i={}, C_Vi={}, R_Vi={}".format(V_i, C_Vi, R_Vi)
				
				R_Vi_int = int(R_Vi, 16)
    				registered_auv[V_i] = R_Vi_int
					
    				with open("registration_db.txt", "a") as f:
        				f.write("{}|{}|{}\n".format(V_i, C_Vi, R_Vi))
				
    				conn.sendall("Registration OK for {}".format(V_i))
				threading.current_thread().conn = conn
				threading.current_thread().vid = V_i
				n = 3
   				if len(registered_auv) == n:
        				calculate_keys(n)
			else:
    				print "[Client {}] {}".format(addr, data)
    				conn.sendall("Server received: {}".format(data))
            		
    	except socket.error:
        	print "[-] Connection lost {}".format(addr)
    	finally:
        	conn.close()
def calculate_keys(n):
    
    	msk_s = 0
    	for r_val in registered_auv.values():
        	msk_s ^= r_val
    	print "[*] Master Secret Key (MSK_s) =", hex(msk_s)

    	for vid, r_val in registered_auv.items():
        	msk_vi = msk_s ^ r_val
        	print "[*] Private key for {} = {}".format(vid, hex(msk_vi))
		try:
    			for thread in threading.enumerate():
        			if hasattr(thread, "conn") and hasattr(thread, "vid") and thread.vid == vid:
            				thread.conn.sendall("Your Private Key: {}\n".format(hex(msk_vi)))
		except:
    			pass

def start_server():
    	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	server_socket.bind((HOST, PORT))
    	server_socket.listen(5)
    	print "[*] Server listening on {}:{}".format(HOST, PORT)

    	while True:
        	conn, addr = server_socket.accept()
        	thread = threading.Thread(target=handle_client, args=(conn, addr))
        	thread.start()

if __name__ == "__main__":
    	start_server()
