README
Overview
This project implements a simplified simulation of an AUV (Autonomous Underwater Vehicle) authentication protocol based on a PUF (Physically Unclonable Function)-assisted key agreement scheme.
It follows three main phases derived from the research paper:

Registration Phase – AUVs manually register with the server. When the required number of AUVs have registered, the server assigns each an individual private key. Challenge-Response Pairs (CRPs) are also generated to emulate PUF behavior, stored in local files.

Authentication Phase – One AUV (initiator) requests authentication with another AUV (responder) through the server, acting as a relay.

Key Agreement Phase – Both AUVs generate random values and exchange them via the server. Using their private key and CRP response, they compute a shared session key (sk) without using any encryption function E—values are sent directly for demonstration purposes.

Mechanism Summary
PUF Simulation
For each AUV 𝑉𝑖, a random Challenge 𝐶𝑉𝑖 and its corresponding Response 𝑅𝑉𝑖 are generated and stored in crp_<ID>.txt. This simulates the unique and unclonable hardware PUF response. System Master Secret Key Each AUV stores its private key 𝑀𝑆𝐾𝑉𝑖 in msk_<ID>.txt. On authentication request, it computes:

𝑀𝑆𝐾𝑠=𝑀𝑆𝐾𝑉𝑖⊕𝑅𝑉𝑖

 
​
 
Random Value Exchange

Initiator generates a random value 𝑎 and sends it (with its ID) to the responder through the server. Responder generates a random value 𝑏 and sends it back to the initiator.

Session Key Generation

Both sides compute the session key:
𝑠𝑘=SHA256(𝑎 ∣∣ 𝑏)

The computed sk is stored locally in sk_<initiatorID>_<responderID>.txt and printed in hex.

Requirements
Python 2.7

No external dependencies (only Python built-in libraries).



Notes
Encryption function E from the original paper is not implemented here; all data exchanges are in plaintext for clarity.

This project is for educational and demonstration purposes only and does not provide production-grade security.

