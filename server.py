# -*- coding: utf-8 -*-
import socket
import threading
import binascii
import os

HOST = '0.0.0.0'
PORT = 5000
REQUIRED_AUVS = 3

registered_auv = {}   # id -> conn
reg_records = {}      # id -> {'C': bytes, 'R': bytes}
lock = threading.Lock()

def b2h(b):
    return binascii.hexlify(b)

def h2b(h):
    return binascii.unhexlify(h)

def bytes_xor(a, b):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

def write_full_db(msk_s_bytes, per_keys_dict):
    with open('registration_db.txt', 'wb') as f:
        f.write('ID,C_hex,R_hex,MSK_V_hex\n')
        for auv_id, rec in reg_records.items():
            msk_v_hex = b2h(per_keys_dict[auv_id]) if auv_id in per_keys_dict else ''
            f.write('{},{},{},{}\n'.format(auv_id, b2h(rec['C']), b2h(rec['R']), msk_v_hex))
    with open('msk_s.txt', 'wb') as f:
        f.write(b2h(msk_s_bytes) + '\n')

def handle_client(conn, addr):
    print "[*] New connection from", addr
    try:
        while True:
            data = conn.recv(8192)
            if not data:
                break
            data = data.strip()
            # parse command by space
            parts = data.split()
            if not parts:
                continue

            cmd = parts[0]

            # REGISTRATION: REG <ID> <C_hex> <R_hex>
            if cmd == "REG" and len(parts) == 4:
                auv_id, c_hex, r_hex = parts[1], parts[2], parts[3]
                try:
                    c_bytes = h2b(c_hex)
                    r_bytes = h2b(r_hex)
                except:
                    conn.sendall("ERR bad hex\n")
                    continue
                with lock:
                    reg_records[auv_id] = {'C': c_bytes, 'R': r_bytes}
                    registered_auv[auv_id] = conn
                    # append registration line (without MSK_V yet)
                    if not os.path.exists('registration_db.txt'):
                        with open('registration_db.txt','wb') as f:
                            f.write('ID,C_hex,R_hex,MSK_V_hex\n')
                    with open('registration_db.txt','ab') as f:
                        f.write('{},{},{},\n'.format(auv_id, c_hex, r_hex))
                conn.sendall("REG_OK {}\n".format(auv_id))
                print "[*] Registered", auv_id, "({}/{})".format(len(reg_records), REQUIRED_AUVS)

                # if enough AUVs, compute MSK_s and per-MSK and send PRIVATE_KEY
                with lock:
                    if len(reg_records) >= REQUIRED_AUVS:
                        msk_s = None
                        for rec in reg_records.values():
                            msk_s = rec['R'] if msk_s is None else bytes_xor(msk_s, rec['R'])
                        per_keys = {}
                        for _id, rec in reg_records.items():
                            per_keys[_id] = bytes_xor(msk_s, rec['R'])
                        write_full_db(msk_s, per_keys)
                        # send keys to connected AUVs
                        for _id, c in registered_auv.items():
                            try:
                                c.sendall("PRIVATE_KEY {}\n".format(b2h(per_keys[_id])))
                                print "[*] Sent PRIVATE_KEY to", _id
                            except Exception as e:
                                print "Failed to send PRIVATE_KEY to", _id, e
                continue

            # AUTH_INIT <from_id> <target_id> <P_Vi_hex>
            if cmd == "AUTH_INIT" and len(parts) == 4:
                from_id = parts[1]
                target_id = parts[2]
                p_hex = parts[3]
                with lock:
                    if target_id not in registered_auv:
                        conn.sendall("ERR target_not_found {}\n".format(target_id))
                    else:
                        target_conn = registered_auv[target_id]
                        try:
                            target_conn.sendall("AUTH_CHALLENGE {} {}\n".format(from_id, p_hex))
                            conn.sendall("AUTH_INIT_OK {}\n".format(target_id))
                            print "[*] Forwarded AUTH_INIT from {} -> {}".format(from_id, target_id)
                        except Exception as e:
                            conn.sendall("ERR forward_fail {}\n".format(target_id))
                continue

            # AUTH_RESPONSE <from_id> <initiator_id> <P_Vj_hex>
            if cmd == "AUTH_RESPONSE" and len(parts) == 4:
                from_id = parts[1]
                initiator_id = parts[2]
                p_hex = parts[3]
                with lock:
                    if initiator_id not in registered_auv:
                        conn.sendall("ERR initiator_not_found {}\n".format(initiator_id))
                    else:
                        init_conn = registered_auv[initiator_id]
                        try:
                            # forward to initiator: AUTH_RESPONSE <from_id> <P_Vj_hex>
                            init_conn.sendall("AUTH_RESPONSE {} {}\n".format(from_id, p_hex))
                            conn.sendall("AUTH_RESPONSE_SENT {}\n".format(initiator_id))
                            print "[*] Forwarded AUTH_RESPONSE from {} -> {}".format(from_id, initiator_id)
                        except Exception as e:
                            conn.sendall("ERR forward_fail {}\n".format(initiator_id))
                continue

            # simple echo fallback
            conn.sendall("Server received: " + data + "\n")

    except Exception as e:
        print "Client handler exception:", e
    finally:
        # cleanup: remove conn from registered_auv if present
        with lock:
            to_del = None
            for k,v in registered_auv.items():
                if v == conn:
                    to_del = k
                    break
            if to_del:
                del registered_auv[to_del]
        try:
            conn.close()
        except:
            pass
        print "[*] Connection closed", addr

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(10)
    print "[*] Server started on {}:{}".format(HOST, PORT)
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    main()

