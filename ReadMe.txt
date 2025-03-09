Project 1: Symmetric Key-Based Authentication Protocol 
- Use DES or AES to encrypt and decrypt messages.
- Pick up your own ID, nonces and symmetric keys. 
1. Alice sends its identity and a nonce NA to Bob.
2. Bob responds a nonce NB and an encrypted message that includes Bob's identity and nonce NA. KAB is the key.
3. Alice sends Bob an encrypted message that includes Alice's identity and nonce NB.

Project 2: Public Key-Based Authentication Protocol
1. Generate RSA public/private key pair.
2. Encrypt and decrypt message using RSA.
3. Pick up ID and nonces by yourself.

Project 3: Digital Signature
- Alice sends Bob a message M with its signature.
- This program should create an RSA key pair and then signs message M and displays the signature.
- Verify the signature with the corresponding public key.
- If signature is verified successfully, the receiver Bob will be able to authenticate Alice.
- *Eliminate replay attack* 

To run this program:
- cd to either Project1, Project2, or Project3
- run: python bob.py
- run: python alice.py

Key Distribution Protocol 
- The server (KDC) is used for exchanged messaged between two clients (Alice and Bob)
Phase 1: Public-Key Scheme is used to distribute master Key K_A and master key K_B 
Phase 2: The KDC generates a session key K_AB and separately sends it to Alice and Bob
- To run:
  - cd Key Distribution Protocol 
  - run: python KDC.py
  - run: python alice.py
  - run: python bob.py

Secure Chat System 
- To run this program:
  - run: python KDC.py in one terminal
  - run: python client.py in another terminal (prompted to enter Client ID) 
  - run: python client.py in a third terminal (prompted to enter Client ID)
  - Can run more clients if desired
  - Type messages in one client to be relayed by the KDC to other clients
