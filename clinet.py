# -*- coding: utf-8 -*-
import socket
import binascii
import hashlib
import os
import threading
import sys
from Crypto.Cipher import AES
from Crypto import Random

SERVER_IP = '127.0.0.1'
SERVER_PORT = 5000

MY_ID = None
PENDING = {}  # pending[peer_id] = {'role':..., 'a':bytes, 'b':bytes}

def b2h(b):
    return binascii.hexlify(b)

def h2b(h):
    return binascii.unhexlify(h)

def sha256_bytes(x):
    return hashlib.sha256(x).digest()

def bytes_xor(a, b):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

# AES helpers (AES-256-CBC, PKCS7 padding)
BLOCK = 16
def pad(s):
    pad_len = BLOCK - (len(s) % BLOCK)
    return s + chr(pad_len) * pad_len

def unpad(s):
    if not s:
        return s
    pad_len = ord(s[-1])
    return s[:-pad_len]

def aes_encrypt(key32, plaintext):
    iv = Random.new().read(16)
    cipher = AES.new(key32, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext))
    return b2h(iv + ct)

def aes_decrypt(key32, hexdata):
    data = h2b(hexdata)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key32, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    return unpad(pt)

# PUF simulation: R = SHA256( ID || C )
def puf_hash(auv_id, challenge_bytes):
    h = hashlib.sha256()
    h.update(auv_id)
    h.update(challenge_bytes)
    return h.digest()

def save_crp(auv_id, C, R):
    with open("crp_{}.txt".format(auv_id), "wb") as f:
        f.write("C={}\nR={}\n".format(b2h(C), b2h(R)))

def load_crp(auv_id):
    fn = "crp_{}.txt".format(auv_id)
    with open(fn, "rb") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    C_hex = lines[0].split("=",1)[1]
    R_hex = lines[1].split("=",1)[1]
    return h2b(C_hex), h2b(R_hex)

def save_msk(auv_id, msk_hex):
    with open("msk_{}.txt".format(auv_id), "wb") as f:
        f.write(msk_hex + "\n")

def load_msk(auv_id):
    fn = "msk_{}.txt".format(auv_id)
    with open(fn, "rb") as f:
        return h2b(f.read().strip())

def recv_thread(sock):
    global MY_ID
    while True:
        try:
            data = sock.recv(8192)
            if not data:
                print "[*] Server closed?"
                break
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                cmd = parts[0]

                if cmd == "REG_OK":
                    print "[*] Registration ok:", parts[1]

                elif cmd == "PRIVATE_KEY":
                    key_hex = parts[1]
                    if MY_ID:
                        save_msk(MY_ID, key_hex)
                        print "[*] Received PRIVATE_KEY and saved -> msk_{}.txt".format(MY_ID)
                    else:
                        print "[*] Received PRIVATE_KEY but MY_ID unknown"

                elif cmd == "AUTH_CHALLENGE":
                    # AUTH_CHALLENGE <from_id> <P_Vi_hex>
                    from_id = parts[1]
                    p_hex = parts[2]
                    print "[*] Received AUTH_CHALLENGE from", from_id
                    # must have own msk and crp to compute MSK_s to decrypt P_Vi
                    if not MY_ID:
                        print "ERR: not registered"
                        continue
                    try:
                        MSK_Vj = load_msk(MY_ID)
                        C_j, R_j = load_crp(MY_ID)
                    except Exception as e:
                        print "ERR: missing local msk or crp:", e
                        continue
                    # recover MSK_s = MSK_Vj xor R_j
                    MSK_s = bytes_xor(MSK_Vj, R_j)
                    try:
                        pt = aes_decrypt(MSK_s, p_hex)
                    except Exception as e:
                        print "ERR decrypt P_Vi:", e
                        continue
                    # plaintext format: initiator_id|a_hex
                    try:
                        initiator_id, a_hex = pt.split('|',1)
                    except:
                        print "ERR bad plaintext format"
                        continue
                    a_bytes = h2b(a_hex)
                    # store pending
                    PENDING[initiator_id] = {'role':'responder', 'a':a_bytes}
                    # generate b and send AUTH_RESPONSE
                    b = os.urandom(16)
                    PENDING[initiator_id]['b'] = b
                    # encrypt (Vj || b) with key derived from a: key = SHA256(a)
                    key_a = sha256_bytes(a_bytes)
                    plaintext2 = MY_ID + "|" + b2h(b)
                    p_vj_hex = aes_encrypt(key_a, plaintext2)
                    # send AUTH_RESPONSE <from_id> <initiator_id> <P_Vj_hex>
                    msg = "AUTH_RESPONSE {} {} {}\n".format(MY_ID, initiator_id, p_vj_hex)
                    try:
                        sock.sendall(msg)
                        print "[*] Sent AUTH_RESPONSE to server (will be forwarded to {})".format(initiator_id)
                    except Exception as e:
                        print "ERR send AUTH_RESPONSE:", e
                    # responder can compute sk now
                    sk_res = hashlib.sha256(a_bytes + b).digest()
                    sk_hex = b2h(sk_res)
                    fname = "sk_{}_{}.txt".format(MY_ID, initiator_id)
                    with open(fname, "wb") as f:
                        f.write(sk_hex + "\n")
                    print "[*] Responder computed sk and saved ->", fname
                    print "[*] Responder sk HEX:", sk_hex

                elif cmd == "AUTH_RESPONSE":
                    # forwarded to initiator: AUTH_RESPONSE <from_id> <P_Vj_hex>
                    from_id = parts[1]
                    p_vj_hex = parts[2]
                    print "[*] Received AUTH_RESPONSE from", from_id
                    # initiator should have stored 'a' in PENDING[from_id]
                    if from_id not in PENDING or 'a' not in PENDING[from_id]:
                        print "ERR: missing a (no pending record)"
                        continue
                    a_bytes = PENDING[from_id]['a']
                    key_a = sha256_bytes(a_bytes)
                    try:
                        pt2 = aes_decrypt(key_a, p_vj_hex)
                    except Exception as e:
                        print "ERR decrypt P_Vj:", e
                        continue
                    # plaintext2: responder_id|b_hex
                    try:
                        responder_id, b_hex = pt2.split('|',1)
                    except:
                        print "ERR bad plaintext2"
                        continue
                    b_bytes = h2b(b_hex)
                    # compute sk = SHA256(a||b)
                    sk = hashlib.sha256(a_bytes + b_bytes).digest()
                    sk_hex = b2h(sk)
                    fname = "sk_{}_{}.txt".format(MY_ID, from_id)
                    with open(fname, "wb") as f:
                        f.write(sk_hex + "\n")
                    print "[*] Initiator computed sk and saved ->", fname
                    print "[*] Initiator sk HEX:", sk_hex
                    # cleanup pending
                    if from_id in PENDING:
                        del PENDING[from_id]

                else:
                    print "[Server] {}".format(line)

        except Exception as e:
            print "Recv thread exception:", e
            break

def main():
    global MY_ID
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, SERVER_PORT))
    print "[*] Connected to server {}:{}".format(SERVER_IP, SERVER_PORT)

    t = threading.Thread(target=recv_thread, args=(s,))
    t.daemon = True
    t.start()

    try:
        while True:
            msg = raw_input("Enter the message: ").strip()
            if not msg:
                continue
            if msg.lower() == "exit":
                break

            # register <ID>
            if msg.startswith("register "):
                parts = msg.split()
                if len(parts) != 2:
                    print "Usage: register <ID>"
                    continue
                auv_id = parts[1]
                MY_ID = auv_id
                # generate C and R (PUF simulated)
                C = os.urandom(16)
                R = puf_hash(auv_id, C)
                save_crp(auv_id, C, R)
                # send REG <ID> <C_hex> <R_hex>
                line = "REG {} {} {}\n".format(auv_id, b2h(C), b2h(R))
                s.sendall(line)
                print "[*] Sent registration. Waiting for server to assign PRIVATE_KEY once enough AUVs registered."

            # auth <target_id>
            elif msg.startswith("auth "):
                parts = msg.split()
                if len(parts) != 2:
                    print "Usage: auth <target_id>"
                    continue
                target = parts[1]
                if not MY_ID:
                    print "Please register first."
                    continue
                # load own MSK_V and CRP to compute MSK_s
                try:
                    MSK_Vi = load_msk(MY_ID)
                    C_i, R_i = load_crp(MY_ID)
                except Exception as e:
                    print "ERR: missing msk or crp locally:", e
                    continue
                MSK_s = bytes_xor(MSK_Vi, R_i)
                # generate a
                a = os.urandom(16)
                PENDING[target] = {'role':'initiator', 'a': a}
                # plaintext: Vi|a_hex
                plaintext = MY_ID + "|" + b2h(a)
                p_vi_hex = aes_encrypt(MSK_s, plaintext)
                # send AUTH_INIT <from_id> <target_id> <P_Vi_hex>
                msgline = "AUTH_INIT {} {} {}\n".format(MY_ID, target, p_vi_hex)
                s.sendall(msgline)
                print "[*] Sent AUTH_INIT to server (will be forwarded to {})".format(target)

            else:
                # send raw to server
                s.sendall(msg + "\n")

    except KeyboardInterrupt:
        pass
    finally:
        try:
            s.close()
        except:
            pass
        print "[*] Client exit"

if __name__ == "__main__":
    main()
