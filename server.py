# -*- coding: utf-8 -*-
import socket
import select

HOST = '0.0.0.0'
PORT = 5000
REGISTERED = {}
EXPECTED_AUVS = 2  # 幾台 AUV 註冊後才發送私鑰

def send(sock, msg):
    sock.sendall(msg + "\n")

def broadcast_msk():
    for auv_id, sock in REGISTERED.items():
        fname_msk = "msk_{}.txt".format(auv_id)
        fname_crp = "crp_{}.txt".format(auv_id)
        # 這裡簡化：直接用固定長度字串模擬
        with open(fname_msk, "wb") as f:
            f.write("K" * 16)  # 假設 16 bytes MSK
        with open(fname_crp, "wb") as f:
            f.write("C" * 16 + "|" + "R" * 16)  # challenge|response
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


