# -*- coding: utf-8 -*-
import socket
import sys
import os
import select
import hashlib

HOST = '127.0.0.1'
PORT = 5000
MY_ID = None

def xor_stream(data, key):
    out = []
    for i in range(len(data)):
        out.append(chr(ord(data[i]) ^ ord(key[i % len(key)])))
    return ''.join(out)

def load_file(filename):
    with open(filename, "rb") as f:
        return f.read()

def main():
    global MY_ID
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("[*] Connected to server {}:{}".format(HOST, PORT))

    msk = None
    challenge = None
    response = None
    a_val = None

    while True:
        ready = select.select([s, sys.stdin], [], [])[0]
        for src in ready:
            if src == s:
                msg = s.recv(4096)
                if not msg:
                    print("[!] Disconnected")
                    return
                for line in msg.strip().split("\n"):
                    parts = line.strip().split(" ", 2)
                    cmd = parts[0]

                    if cmd == "MSK_READY":
                        rid = parts[1]
                        print("[*] Received MSK_READY for {}".format(rid))

                    elif cmd == "AUTH_INIT":
                        from_id = parts[1]
                        print("[*] AUTH_INIT from {}".format(from_id))

                    elif cmd == "A_MSG":
                        from_id, payload_hex = parts[1], parts[2]
                        # 計算 MSK_s
                        msk = load_file("msk_{}.txt".format(MY_ID))
                        crp = load_file("crp_{}.txt".format(MY_ID))
                        challenge, response = crp.split("|", 1)
                        msk_s = ''.join(chr(ord(msk[i]) ^ ord(response[i])) for i in range(len(msk)))
                        # 解出 initiator 的 a
                        decrypted = xor_stream(payload_hex.decode("hex"), msk_s)
                        init_id, a_val = decrypted.split("|", 1)
                        print("[*] Received a from {}: {}".format(init_id, a_val.encode("hex")))
                        # 產生 b 並回傳
                        b_val = os.urandom(8)
                        payload_b = xor_stream(MY_ID + "|" + b_val, msk_s).encode("hex")
                        s.sendall("FORWARD_B {} {}\n".format(from_id, payload_b))
                        # 計算 SK (Responder)
                        sk = hashlib.sha256(a_val + b_val).hexdigest()
                        print("[*] Final SK (Responder):", sk)

                    elif cmd == "B_MSG":
                        from_id, payload_hex = parts[1], parts[2]
                        msk = load_file("msk_{}.txt".format(MY_ID))
                        crp = load_file("crp_{}.txt".format(MY_ID))
                        challenge, response = crp.split("|", 1)
                        msk_s = ''.join(chr(ord(msk[i]) ^ ord(response[i])) for i in range(len(msk)))
                        decrypted = xor_stream(payload_hex.decode("hex"), msk_s)
                        resp_id, b_val = decrypted.split("|", 1)
                        print("[*] Received b from {}: {}".format(resp_id, b_val.encode("hex")))
                        sk = hashlib.sha256(a_val + b_val).hexdigest()
                        print("[*] Final SK (Initiator):", sk)

            else:
                cmd = sys.stdin.readline().strip()
                if cmd.startswith("register"):
                    MY_ID = cmd.split(" ")[1]
                    s.sendall(cmd + "\n")
                elif cmd.startswith("auth"):
                    target_id = cmd.split(" ")[1]
                    # 計算 MSK_s
                    msk = load_file("msk_{}.txt".format(MY_ID))
                    crp = load_file("crp_{}.txt".format(MY_ID))
                    challenge, response = crp.split("|", 1)
                    msk_s = ''.join(chr(ord(msk[i]) ^ ord(response[i])) for i in range(len(msk)))
                    # 產生 a
                    a_val = os.urandom(8)
                    payload_a = xor_stream(MY_ID + "|" + a_val, msk_s).encode("hex")
                    s.sendall("FORWARD_A {} {}\n".format(target_id, payload_a))

if __name__ == "__main__":
    main()

