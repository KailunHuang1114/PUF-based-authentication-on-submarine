Underwater AUV Authentication & Key Exchange System
Overview
This project implements a PUF-based authentication and session key establishment mechanism for autonomous underwater vehicles (AUVs) and a central server, inspired by the referenced paper. The goal is to allow secure mutual authentication and encrypted communication between multiple AUVs in a marine environment.

The system consists of three main stages:

AUV Registration

Each AUV generates a challenge (C) and uses its internal PUF to calculate a response (R).

The AUV sends its ID, challenge, and response to the server over a secure channel.

The server computes a system master secret key (MSK_s) as the XOR of all AUV responses and assigns each AUV a private key (MSK_Vi) derived from MSK_s.

AUV Update

When a new AUV joins, the server updates MSK_s and all AUV private keys using XOR with the new AUV's response.

The updated private keys are securely sent to all registered AUVs.

Authentication & Session Key Establishment

When an AUV wants to authenticate with another AUV, the initiator calculates MSK_s using its private key and PUF response.

Random nonces (a and b) are exchanged through the server acting as a relay.

Each message is encrypted using XOR stream cipher with the calculated keys.

After exchanging nonces, both AUVs compute the session key (sk) as sk = H(a || b) using a hash function, ensuring a consistent and secure session key for communication.

Note: The PUF functionality is simulated using SHA-256 hashing, and files are used to store keys and challenges for simplicity.

Requirements
Python 2.7

No external packages required (uses only standard library)

Files
server.py — Server program handling AUV registration, key assignment, and message forwarding.

client.py — AUV client program capable of registering with the server and authenticating with other AUVs.

msk_<AUV_ID>.txt — Private key file for each registered AUV (generated automatically).

crp_<AUV_ID>.txt — Challenge file for each registered AUV (generated automatically).

Usage
Start the Server


python server.py
The server listens on all interfaces at port 5000.

Start AUV Clients
Open separate terminals for each AUV:


python client.py
Enter a unique ID when prompted, e.g., v1 or v2.

Register AUVs
In each client terminal, register the AUV with the server:

register v1
register v2
Once the expected number of AUVs have registered, the server generates MSK and challenge files, sending MSK_READY notification to clients.

Authenticate AUVs
To initiate authentication from one AUV to another:


auth <target_ID>
Example:


auth v2
The server relays messages between AUVs, simulating the PUF-based authentication and XOR-based encrypted nonce exchange.

Example Output
Client 1 (Initiator):


[*] Connected to server 127.0.0.1:5000
[*] Keys loaded for v1
[*] Final SK (Initiator): e3b0c44298fc1c149afbf4c8996fb924...
Client 2 (Responder):


[*] Connected to server 127.0.0.1:5000
[*] Keys loaded for v2
[*] Final SK (Responder): e3b0c44298fc1c149afbf4c8996fb924...
The session key (sk) is identical for both AUVs.

Notes
Messages between clients use a pipe | separator to avoid parsing errors.

The XOR stream cipher is used to encrypt data in transit instead of standard AES for simplicity.

PUF responses are simulated using SHA-256; in real-world applications, actual PUF hardware should be used.

The system is designed to be manual-command driven (register and auth) to illustrate the full mechanism.
