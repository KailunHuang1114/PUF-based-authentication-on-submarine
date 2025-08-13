# -*- coding: utf-8 -*-
import socket
import threading
import os
import binascii
import hashlib

HOST = '0.0.0.0'  
PORT = 5000       

clients = []  
registered_auv = {}  
AUV_REQUIRED = 2
DB_FILE = 'registration_db.txt'
reg_records = {}  

def bytes_xor(a, b):
    	return ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b))

def b2h(b):
    	return binascii.hexlify(b)

def h2b(h):
    	return binascii.unhexlify(h)

def write_full_db(msk_s_bytes, per_keys_dict):
    
    	with open(DB_FILE, 'wb') as f:
        	f.write('ID,C_hex,R_hex,MSK_V_hex\n')
        	for auv_id, rec in reg_records.items():
            		msk_v_hex = b2h(per_keys_dict[auv_id]) if auv_id in per_keys_dict else ''
            		f.write('{},{},{},{}\n'.format(
                		auv_id, b2h(rec['C']), b2h(rec['R']), msk_v_hex
            		))
    	with open('msk_s.txt', 'wb') as f:
        	f.write(b2h(msk_s_bytes) + '\n')

def append_db_line_on_register(auv_id, c_hex, r_hex):
    
    	if not os.path.exists(DB_FILE):
        	with open(DB_FILE, 'wb') as f:
            		f.write('ID,C_hex,R_hex,MSK_V_hex\n')
    	with open(DB_FILE, 'ab') as f:
        	f.write('{},{},{},\n'.format(auv_id, c_hex, r_hex))
def handle_client(conn, addr):
    	print("[+] new connection:{}:{}".format(addr[0], addr[1]))
    	while True:
        	try:

            		data = conn.recv(4096)
			parts = data.strip().split()
			if parts[0] == "AUTH_RESPONSE" and len(parts) == 4:
				from_id = parts[1]
    				target_id = parts[2]
    				b_hex = parts[3]
				if target_id not in registered_auv:
        				conn.sendall("ERR target_not_found {}".format(target_id))
        				continue
				target_conn = registered_auv[target_id]
				try:
        				target_conn.sendall("AUTH_RESPONSE {} {}".format(from_id, b_hex))
        				conn.sendall("AUTH_RESPONSE_SENT {}".format(target_id))
					print("[*] send b={} from {} -> {}".format(b_hex, from_id, target_id))
    				except:
        				conn.sendall("ERR forward_fail {}".format(target_id))
    				continue

			if parts[0] == "AUTH_INIT" and len(parts) == 4:
				from_id = parts[1]
    				target_id = parts[2]
    				a_hex = parts[3]
				if target_id not in registered_auv:
        				conn.sendall("ERR target_not_found {}".format(target_id))
        				continue
				target_conn = registered_auv[target_id]

				try:
        				target_conn.sendall("AUTH_CHALLENGE {} {}".format(from_id, a_hex))
        				conn.sendall("AUTH_INIT_OK {}".format(target_id))
        				print("[*] send a={} from {} -> {}".format(a_hex, from_id, target_id))
    				except:
        				conn.sendall("ERR forward_fail {}".format(target_id))
    				continue


			if len(parts) >= 1 and parts[0] == 'REG':
    				if len(parts) != 4:
        				conn.sendall("ERR bad REG format")
        				continue
    				auv_id, c_hex, r_hex = parts[1], parts[2], parts[3]
				try:
        				c_bytes = h2b(c_hex)
        				r_bytes = h2b(r_hex)
    				except:
        				conn.sendall("ERR bad hex")
        				continue
				reg_records[auv_id] = {'C': c_bytes, 'R': r_bytes}
    				registered_auv[auv_id] = conn
    				append_db_line_on_register(auv_id, c_hex, r_hex)
    				conn.sendall("REG_OK {}".format(auv_id))
    				print("[*] AUV {} register finished ( {}/{})".format(auv_id, len(reg_records), AUV_REQUIRED))
    				
			 	if len(reg_records) >= AUV_REQUIRED:
       
        				msk_s = None
        				for rec in reg_records.values():
            					msk_s = rec['R'] if msk_s is None else bytes_xor(msk_s, rec['R'])

        
        				per_keys = {}
        				for _id, rec in reg_records.items():
            					per_keys[_id] = bytes_xor(msk_s, rec['R'])

       
        				write_full_db(msk_s, per_keys)

       
        				for _id, c in registered_auv.items():
            					try:
                					c.sendall("PRIVATE_KEY {}".format(b2h(per_keys[_id])))
            					except:
                					pass
        				print("[*] pk sent MSK_s had been witten into msk_s.txt")
    				continue  
            		
            		
            		
        	except:
            		break
    	print("[-] close the connection{}:{}".format(addr[0], addr[1]))
    	conn.close()
    	clients.remove(conn)

def main():
    	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    	s.bind((HOST, PORT))
    	s.listen(5)
    	print("[*] Waiting for connection...")

    	while True:
        	conn, addr = s.accept()
        	clients.append(conn)
        	t = threading.Thread(target=handle_client, args=(conn, addr))
        	t.daemon = True
        	t.start()

if __name__ == "__main__":
    	main()

