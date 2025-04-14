import asyncio
from crypto_utils import (
    generate_signature_keypair, sign, verify_signature,
    serialize_public_key, load_signature_public_key,
    generate_dh_keypair, diffie_hellman, load_dh_public_key,
    hkdf, encrypt, decrypt,
    ratchet_dh_recv, ratchet_dh_send,
    derive_chain_key, derive_message_key
)
from utils import alice_server, prompt, show, read_message_from_stdin
from cryptography.hazmat.primitives import serialization

# Довготермінові ключі Alice
long_term_priv, long_term_pub = generate_signature_keypair()

# Тимчасові DH ключі Alice
dh_priv, dh_pub = generate_dh_keypair()

# Публічний ключ Bob (отримуємо після з'єднання)
bob_long_term_pub = None

peer_dh_pub = None
root_key = None
send_chain_key = None
recv_chain_key = None
initial_sent = False
prev_peer_dh_pub = None

#Обробка вхідного повідомлення
async def receive(reader):
    global bob_long_term_pub, peer_dh_pub, root_key, recv_chain_key, dh_priv, dh_pub
    while True:
        try:
            if not bob_long_term_pub:
                data = await reader.read(32)
                print("[Alice] Received Bob's public key:", data.hex())
                bob_long_term_pub = load_signature_public_key(data)
                continue
            
            header = await reader.readexactly(5)
            
            
            if header == b"11111":  #Блок технологічного обміну
                print("[Alice] Received initial handshake")
                peer_dh_bytes = await reader.readexactly(32)
                signature = await reader.readexactly(64)

                peer_dh_pub = load_dh_public_key(peer_dh_bytes)
                if not verify_signature(peer_dh_bytes, signature, bob_long_term_pub):
                    print("[!] Invalid signature from Bob's 11111 DH key!")
                    return

                shared_secret = diffie_hellman(dh_priv, peer_dh_pub)
                root_key, recv_chain_key = hkdf(shared_secret, salt=None)
                prompt()             
                continue
            else:
                #Обробка вхідного повідомлення в сесії               
                ct_len_bytes = header[:2]
                ct_len = int.from_bytes(ct_len_bytes, 'big')
                ciphertext = header[2:] + await reader.readexactly(ct_len - len(header[2:]))
                                       
                
                nonce = await reader.readexactly(12)
                peer_dh_bytes = await reader.readexactly(32)
                signature = await reader.readexactly(64)

                print("[Alice] Received DH pub:", peer_dh_bytes.hex())
                print("[Alice] Received signature:", signature.hex())

                new_peer_dh_pub = load_dh_public_key(peer_dh_bytes)

                if not verify_signature(peer_dh_bytes, signature, bob_long_term_pub):
                    print("[!] Invalid signature from Bob's DH key!")
                    continue
                
                #Коли приходить новий ключ DH, то проводимо ratchet та генерацію нової ключової пари DH
                if peer_dh_pub is None or new_peer_dh_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ) != peer_dh_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                ):
                    
                    peer_dh_pub = new_peer_dh_pub
                    root_key, recv_chain_key = ratchet_dh_recv(root_key, dh_priv, peer_dh_pub)
                    print("[Alice] Root key after ratchet_dh_recv:", root_key.hex())
                    dh_priv, dh_pub = generate_dh_keypair()

                                                      

                msg_key, recv_chain_key = derive_message_key(recv_chain_key)
                print("[Alice] Recv chain key:", recv_chain_key.hex())
                print("[Alice] Decrypting with key:", msg_key.hex())
                print("[Alice] Root key:", root_key.hex())

                try:
                    plaintext = decrypt(ciphertext, nonce, msg_key).decode()
                    show(plaintext)
                except Exception as e:
                    print("[!] Error during decryption:", type(e).__name__, str(e))

                prompt()
                

        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
            break

#Блок надсилання повідомлення
async def send(writer):
    global dh_priv, dh_pub, initial_sent, root_key, send_chain_key, peer_dh_pub, prev_peer_dh_pub
    if not initial_sent:
        writer.write(b"00000")
        dh_pub_bytes = serialize_public_key(dh_pub)
        signature = sign(dh_pub_bytes, long_term_priv)
        writer.write(dh_pub_bytes)
        writer.write(signature)
        await writer.drain()
        print("[Alice] Sent DH pub:", dh_pub_bytes.hex())
        initial_sent = True
     

    while True:
        message = await read_message_from_stdin()
        plaintext = message.strip().encode()

        if root_key is None or peer_dh_pub is None:
            print("[!] Shared key not established. Cannot send.")
            continue
        
        # Виконати ретчет тільки якщо з’явився новий peer_dh_pub
        if prev_peer_dh_pub is None or peer_dh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ) != prev_peer_dh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ):
            dh_priv, dh_pub = generate_dh_keypair()
            root_key, send_chain_key = ratchet_dh_send(root_key, dh_priv, peer_dh_pub)
            prev_peer_dh_pub = peer_dh_pub
            print("[Alice] Root key after DH Ratchet (before encrypt):", root_key.hex())
        
        msg_key, send_chain_key = derive_message_key(send_chain_key)

        print("[Alice] Root key before encrypt:", root_key.hex())
        print("[Alice] Send chain key:", send_chain_key.hex())
        print("[Alice] Message key:", msg_key.hex())

        ciphertext, nonce = encrypt(plaintext, msg_key)
        ct_len = len(ciphertext)

        print("[Alice] Encrypting with key:", msg_key.hex())
        writer.write(ct_len.to_bytes(2, 'big'))
        writer.write(ciphertext)
        writer.write(nonce)

        dh_pub_bytes = serialize_public_key(dh_pub)
        signature = sign(dh_pub_bytes, long_term_priv)
        writer.write(dh_pub_bytes)
        writer.write(signature)

        await writer.drain()
        prompt()

async def init_connection(reader, writer):
    print("Connected with Bob!")

    alice_pub_key_bytes = serialize_public_key(long_term_pub)
    writer.write(alice_pub_key_bytes)
    await writer.drain()

    prompt()
    await asyncio.gather(receive(reader), send(writer))

if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
