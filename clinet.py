# -*- coding: utf-8 -*-
import socket
import os
import binascii
import hashlib

MY_ID = None  
SERVER_IP = '127.0.0.1'  
SERVER_PORT = 5000


PENDING = {} 
def puf_hash(auv_id, challenge_bytes):
    
    	h = hashlib.sha256()
   
    	h.update(auv_id)
    	h.update(challenge_bytes)
    	return h.digest()  
def h2b(h): 
    	return binascii.unhexlify(h)
def b2h(b):
	
    	return binascii.hexlify(b)
def load_msk(auv_id):
    
    	with open("msk_{}.txt".format(auv_id), "rb") as f:
        	return h2b(f.read().strip())

def load_crp(auv_id):
    
    	with open("crp_{}.txt".format(auv_id), "rb") as f:
        	lines = [x.strip() for x in f.readlines() if x.strip()]
    	C_hex = lines[0].split("=", 1)[1]
    	R_hex = lines[1].split("=", 1)[1]
    	return h2b(C_hex), h2b(R_hex)
def bytes_xor(a, b):
    	return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))


def main():
    	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	s.connect((SERVER_IP, SERVER_PORT))
    	print("[*] Connected to server {}:{}".format(SERVER_IP, SERVER_PORT))

    	try:
        	while True:
            		msg = raw_input("Enter the message: ")
			if msg.startswith("register "):
    				parts = msg.strip().split()
    				if len(parts) != 2:
        				print("format: register <AUV_ID>")
        				continue
    				auv_id = parts[1]
    				C = os.urandom(16)     
    				R = puf_hash(auv_id, C) 
				
    				line = "REG {} {} {}\n".format(auv_id, b2h(C), b2h(R))
    				s.sendall(line)
    				MY_ID = auv_id
				with open("crp_{}.txt".format(auv_id), "wb") as f:
    					f.write("C={}\nR={}\n".format(b2h(C), b2h(R)))
    				continue
			if msg.startswith("auth "):
				parts = msg.strip().split()
    				if len(parts) != 2:
        				print("usage : auth <TARGET_ID>")
        				continue
    				target_id = parts[1]
				if not MY_ID:
        				print("please register first")
       			 		continue

				C, R = load_crp(MY_ID)
    				MSK_Vi = load_msk(MY_ID)
    				MSK_s = bytes_xor(MSK_Vi, R)
    				a = os.urandom(16) 
    				line = "AUTH_INIT {} {} {}".format(MY_ID, target_id, b2h(a))
    				s.sendall(line)
    				print("[*] sent auth initial to {}, a={} (hex)".format(target_id, b2h(a)))
    				continue

            		if msg.strip().lower() == "exit":
                		break
            		#s.sendall(msg)

            		data = s.recv(4096)
            		if not data:
    				break

			if data.startswith("REG_OK"):
    				print("[*] register finished: {}".format(data))
			elif data.startswith("PRIVATE_KEY "):
    				key_hex = data.split()[1]
    				fname = "msk_{}.txt".format(MY_ID if MY_ID else "unknown")
    				with open(fname, 'wb') as f:
        				f.write(key_hex + "\n")
    				print("[*] save pk -> {}".format(fname))	
			elif data.startswith("AUTH_CHALLENGE "):
    				parts = data.strip().split()
    				from_id = parts[1]
    				a_hex = parts[2]
    				print("[*] recieve {} challenge a={}".format(from_id, a_hex))
				
				a_bytes = h2b(a_hex)
    				PENDING[from_id] = {'role':'responder', 'a': a_bytes}

				b = os.urandom(16)  
    				PENDING[from_id]['b'] = b

				if not MY_ID:
        				print("ERR not reg yet，no crp")
    				else:
        				line = "AUTH_RESPONSE {} {} {}".format(MY_ID, from_id, b2h(b))
        				s.sendall(line)
        				print("[*] Sent b={} to server to {}".format(b2h(b), from_id))

				

			elif data.startswith("AUTH_RESPONSE "):
				parts = data.strip().split()
    				from_id = parts[1]   
    				b_hex = parts[2]
				print("[*] received {} b={}".format(from_id, b_hex))
    				b_bytes = h2b(b_hex)
				if from_id not in PENDING or PENDING[from_id].get('role') != 'initiator':

        				print("ERR: cannot find chal (a)")

				else:
        				a_bytes = PENDING[from_id]['a']
        
        				sk = sha256_bytes(a_bytes + b_bytes)
        				
        				sk_hex = b2h(sk)
					
					print("[*](sk) HEX: {}".format(sk_hex))
					print("[*](sk) HEX: {}".format(sk_hex))
        				fname = "sk_{}_{}.txt".format(MY_ID, from_id) 
        				with open(fname, "wb") as f:
            					f.write(sk_hex + "\n")

        				print("[*] calculate session key -> {}".format(fname))
					print("[*](sk) HEX: {}".format(sk_hex))
        				
        				del PENDING[from_id]
			else:
    				print("receive from server : " + data)
    	except KeyboardInterrupt:
        	pass

    	s.close()
	
    	print("The connection has closed")
		
if __name__ == "__main__":
    	main()
