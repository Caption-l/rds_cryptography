import asyncio
from crypto_utils import (
    generate_signature_keypair, sign, verify_signature,
    serialize_public_key, load_signature_public_key,
    generate_dh_keypair, diffie_hellman, load_dh_public_key,
    hkdf, encrypt, decrypt,
    ratchet_dh_send, ratchet_dh_recv,
    derive_message_key, derive_chain_key
)
from utils import bob_client, prompt, show, read_message_from_stdin
from cryptography.hazmat.primitives import serialization

# Довготермінові ключі Bob
long_term_priv, long_term_pub = generate_signature_keypair()

# Тимчасові DH ключі Bob
dh_priv, dh_pub = generate_dh_keypair()
import asyncio
from crypto_utils import (
    generate_signature_keypair, sign, verify_signature,
    serialize_public_key, load_signature_public_key,
    generate_dh_keypair, diffie_hellman, load_dh_public_key,
    hkdf, encrypt, decrypt,
    ratchet_dh_recv, ratchet_dh_send,
    derive_chain_key, derive_message_key
)
from utils import bob_client, prompt, show, read_message_from_stdin
from cryptography.hazmat.primitives import serialization

# Довготермінові ключі Bob
long_term_priv, long_term_pub = generate_signature_keypair()

# Тимчасові DH ключі Bob
dh_priv, dh_pub = generate_dh_keypair()

# Публічний ключ Alice (отримується при першому повідомленні)
alice_long_term_pub = None

peer_dh_pub = None
root_key = None
send_chain_key = None
recv_chain_key = None
prev_peer_dh_pub = None

#Обробка вхідного повідомлення
async def receive(reader, writer):
    global alice_long_term_pub, peer_dh_pub, root_key, recv_chain_key, dh_priv, dh_pub
    while True:
        try:
            if not alice_long_term_pub:
                data = await reader.read(32)
                print("[Bob] Received Alice's public key bytes:", data.hex())
                alice_long_term_pub = load_signature_public_key(data)
                continue

            header = await reader.readexactly(5)

            if header == b"00000": #Блок технологічного обміну
                print("[Bob] Received initial handshake")
                peer_dh_bytes = await reader.readexactly(32)
                signature = await reader.readexactly(64)
                
                peer_dh_pub = load_dh_public_key(peer_dh_bytes)
                if not verify_signature(peer_dh_bytes, signature, alice_long_term_pub):
                    print("[!] Initial DH signature invalid!")
                    continue

                shared_secret = diffie_hellman(dh_priv, peer_dh_pub)
                root_key, send_chain_key = hkdf(shared_secret, salt=None)
                recv_chain_key = send_chain_key
                
                prompt()
                                
                # Відправка технологічного підтвердження + DH ключ Боба
                print("[Bob] Sending initial handshake response")
                writer.write(b"11111")
                dh_pub_bytes = serialize_public_key(dh_pub)
                signature = sign(dh_pub_bytes, long_term_priv)
                writer.write(dh_pub_bytes)
                writer.write(signature)
                await writer.drain()
                continue
            else:
                #Обробка вхідного повідомлення в сесії
                ct_len = int.from_bytes(header[:2], 'big')
                ciphertext = header[2:] + await reader.readexactly(ct_len - len(header[2:]))
                
                nonce = await reader.readexactly(12)
            
                peer_dh_bytes = await reader.readexactly(32)
                print("[Bob] Received DH pub:", peer_dh_bytes.hex())
                signature = await reader.readexactly(64)
                print("[Bob] Received signature:", signature.hex())

                new_peer_dh_pub = load_dh_public_key(peer_dh_bytes)
                if not verify_signature(peer_dh_bytes, signature, alice_long_term_pub):
                    print("[!] Invalid signature from Alice's DH key!")
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
                    print("[Bob] Root key after DH Ratchet:", root_key.hex())
                    dh_priv, dh_pub = generate_dh_keypair()
                    
                    
                msg_key, recv_chain_key = derive_message_key(recv_chain_key)
                
                print("[Bob] Root key:", root_key.hex())
                print("[Bob] Recv chain key:", recv_chain_key.hex())
                print("[Bob] Message key:", msg_key.hex())

                try:
                    plaintext = decrypt(ciphertext, nonce, msg_key).decode()
                    show(plaintext)
                except Exception as e:
                    print("[!] Error during decryption:", type(e).__name__, str(e))
                    continue

                prompt()

        except Exception as e:
            print("[!] Error occurred while receiving:")
            import traceback
            traceback.print_exc()
            break

#Блок надсилання повідомлення
async def send(writer):
    global dh_priv, dh_pub, root_key, send_chain_key, peer_dh_pub, prev_peer_dh_pub
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
            print("[Bob] Root key before DH Ratchet:", root_key.hex())
            root_key, send_chain_key = ratchet_dh_send(root_key, dh_priv, peer_dh_pub)
            prev_peer_dh_pub = peer_dh_pub
            print("[Bob] Root key after DH Ratchet (before encrypt):", root_key.hex())

                
            
        msg_key, send_chain_key = derive_message_key(send_chain_key)
        print("[Bob] Root key before encrypt:", root_key.hex())
        print("[Bob] Send chain key:", send_chain_key.hex())
        print("[Bob] Message key:", msg_key.hex())

        ciphertext, nonce = encrypt(plaintext, msg_key)

        writer.write(len(ciphertext).to_bytes(2, 'big'))
        writer.write(ciphertext)
        writer.write(nonce)

        dh_pub_bytes = serialize_public_key(dh_pub)
        signature = sign(dh_pub_bytes, long_term_priv)
        print("[Bob] Sending DH pub:", dh_pub_bytes.hex())
        
        writer.write(dh_pub_bytes)
        writer.write(signature)
        await writer.drain()
        prompt()

async def init_connection():
    reader, writer = await bob_client()
    print("Connected to Alice!")

    bob_pub_key_bytes = serialize_public_key(long_term_pub)
    print("[Bob] Sending public key:", bob_pub_key_bytes.hex())
    writer.write(bob_pub_key_bytes)
    await writer.drain()

    prompt()
    await asyncio.gather(receive(reader, writer), send(writer))

if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
