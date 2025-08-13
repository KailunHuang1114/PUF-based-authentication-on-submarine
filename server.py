# -*- coding: utf-8 -*-
import socket
import select
import os
import hashlib

HOST = '0.0.0.0'
PORT = 5000
REGISTERED = {}
EXPECTED_AUVS = 2  # 幾台 AUV 註冊後才發送私鑰

def send(sock, msg):
    sock.sendall(msg + "\n")
def broadcast_msk():
    """當湊齊數量後，生成每台 AUV 的 MSK 與 CRP 並發送"""
    # 先產生每台 AUV 的 challenge 與 response
    crp_dict = {}
    for auv_id in REGISTERED.keys():
        challenge = os.urandom(16)  # 隨機 16 bytes
        response = hashlib.sha256(challenge).digest()[:16]  # 用 hash 模擬 PUF
        crp_dict[auv_id] = (challenge, response)
        # 存成檔案
        with open("crp_{}.txt".format(auv_id), "wb") as f:
            f.write(challenge+ "|" + response )

    # 計算系統主私鑰 MSK_s = R(V1) XOR R(V2) XOR ...
    all_responses = [r for (c, r) in crp_dict.values()]
    msk_s = all_responses[0]
    for r in all_responses[1:]:
        msk_s = "".join([chr(ord(a) ^ ord(b)) for a, b in zip(msk_s, r)])

    # 每台 AUV 的私鑰 MSK_Vi = MSK_s XOR R(Vi)
    for auv_id, sock in REGISTERED.items():
        Rvi = crp_dict[auv_id][1]
        msk_vi = "".join([chr(ord(a) ^ ord(b)) for a, b in zip(msk_s, Rvi)])
        # 存成檔案
        with open("msk_{}.txt".format(auv_id), "wb") as f:
            f.write(msk_vi)
        send(sock, "MSK_READY {}".format(auv_id))

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print("[*] Server listening on {}:{}".format(HOST, PORT))

    sockets = [server]
    A_to_B = {}  # 存 initiator -> (target_id, payload_a)

    while True:
        readable, _, _ = select.select(sockets, [], [])
        for sock in readable:
            if sock == server:
                client_sock, addr = server.accept()
                sockets.append(client_sock)
                print("[*] New connection from", addr)
            else:
                try:
                    data = sock.recv(4096)
                except:
                    data = None
                if not data:
                    sockets.remove(sock)
                    # 移除 REGISTERED 裡對應的
                    for k, v in REGISTERED.items():
                        if v == sock:
                            del REGISTERED[k]
                            break
                    sock.close()
                    continue

                for line in data.strip().split("\n"):
                    parts = line.strip().split(" ", 2)
                    cmd = parts[0]

                    # register <ID>
                    if cmd == "register":
                        auv_id = parts[1]
                        REGISTERED[auv_id] = sock
                        print("[*] {} registered".format(auv_id))
                        if len(REGISTERED) >= EXPECTED_AUVS:
                            broadcast_msk()

                    # FORWARD_A <target_ID> <payload_a>
                    elif cmd == "FORWARD_A":
                        target_id, payload_a = parts[1], parts[2]
                        # 找 target socket
                        if target_id in REGISTERED:
                            from_id = None
                            for k, v in REGISTERED.items():
                                if v == sock:
                                    from_id = k
                                    break
                            if from_id:
                                A_to_B[from_id] = (target_id, payload_a)
                                send(REGISTERED[target_id], "A_MSG {} {}".format(from_id, payload_a))

                    # FORWARD_B <target_ID> <payload_b>
                    elif cmd == "FORWARD_B":
                        target_id, payload_b = parts[1], parts[2]
                        if target_id in REGISTERED:
                            from_id = None
                            for k, v in REGISTERED.items():
                                if v == sock:
                                    from_id = k
                                    break
                            send(REGISTERED[target_id], "B_MSG {} {}".format(from_id, payload_b))

if __name__ == "__main__":
    main()


