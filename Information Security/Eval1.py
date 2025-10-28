Variation 13-ElGamal + ElGamal Signatures + SHA-256:

   

server:
import socket
import threading
import pickle
from random import randint
from hashlib import sha256

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt(m, pub):
    p, g, y = pub
    k = randint(2, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return (a, b)

def elgamal_decrypt(c, priv, pub):
    a, b = c
    p, g, y = pub
    s = pow(a, priv, p)
    s_inv = modinv(s, p)
    return (b * s_inv) % p

def elgamal_sign(msg, p, g, x):
    h = int.from_bytes(sha256(msg.encode()).digest(), "big")
    while True:
        k = randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(msg, sig, p, g, y):
    r, s = sig
    h = int.from_bytes(sha256(msg.encode()).digest(), "big")
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

p_val, g_val = 1223, 2
elgamal_pub, elgamal_priv = generate_elgamal_keys(p_val, g_val)

server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [elgamal_encrypt(m, elgamal_pub) for m in txns]
    total_enc = encrypted_txns[0]
    for c in encrypted_txns[1:]:
        total_enc = ((total_enc[0] * c[0]) % p_val, (total_enc[1] * c[1]) % p_val)
    decrypted_txns = [elgamal_decrypt(c, elgamal_priv, elgamal_pub) for c in encrypted_txns]
    total_dec = elgamal_decrypt(total_enc, elgamal_priv, elgamal_pub)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = elgamal_sign(summary, p_val, g_val, elgamal_priv)
    verify = elgamal_verify(summary, signature, p_val, g_val, elgamal_pub[2])
    sig_status = "Signed"
    verification = "Valid" if verify else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    data = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(data))
    conn.close()

def print_summary():
    print()
    for rec in server_summary:
        print(rec[:-1])

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54330))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()


client:

import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54330))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()


Variation 14: ElGamal + Schnorr Signatures + SHA-256:

Server:
import socket
import threading
import pickle
from random import randint
from hashlib import sha256

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt(m, pub):
    p, g, y = pub
    k = randint(2, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return (a, b)

def elgamal_decrypt(c, priv, pub):
    a, b = c
    p, g, y = pub
    s = pow(a, priv, p)
    s_inv = modinv(s, p)
    return (b * s_inv) % p

def schnorr_gen(p, q, g):
    x = randint(1, q - 1)
    y = pow(g, x, p)
    return (p, q, g, y), x

def schnorr_sign(msg, p, q, g, x):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = int.from_bytes(sha256((str(r) + msg).encode()).digest(), "big") % q
    s = (k + x * e) % q
    return e, s

def modinv_alt(a, m):
    return modinv(a, m)

def schnorr_verify(msg, sig, p, q, g, y):
    e, s = sig
    rv = (pow(g, s, p) * modinv_alt(pow(y, e, p), p)) % p
    ev = int.from_bytes(sha256((str(rv) + msg).encode()).digest(), "big") % q
    return ev == e

p_val, q_val, g_val = 1223, 61, 2
spub, spriv = schnorr_gen(p_val, q_val, g_val)
pub, priv = generate_elgamal_keys(p_val, g_val)

server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [elgamal_encrypt(m, pub) for m in txns]
    total_enc = encrypted_txns[0]
    for c in encrypted_txns[1:]:
        total_enc = ((total_enc[0] * c[0]) % p_val, (total_enc[1] * c[1]) % p_val)
    decrypted_txns = [elgamal_decrypt(c, priv, pub) for c in encrypted_txns]
    total_dec = elgamal_decrypt(total_enc, priv, pub)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    e_s, s_s = schnorr_sign(summary, p_val, q_val, g_val, spriv)
    sig_status = "Signed"
    ver = "Valid" if schnorr_verify(summary, (e_s, s_s), p_val, q_val, g_val, spub[3]) else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, ver, (e_s, s_s)])
    data = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, (e_s, s_s), summary, ver]
    conn.sendall(pickle.dumps(data))
    conn.close()

def print_summary():
    print()
    for rec in server_summary:
        print(rec[:-1])

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54331))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()


Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54331))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, sig, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", sig)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()



Variation 15: RSA Homomorphic + RSA Signatures + SHA-1:

Server:
import socket
import threading
import pickle
from random import randint
from hashlib import sha1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gen_rsa_keys():
    p = 89
    q = 97
    n = p * q
    phi = (p-1)*(q-1)
    e = 17
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (n, e), d

def rsa_encrypt(m, pub):
    n, e = pub
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def rsa_sign(msg, d, n):
    h = int.from_bytes(sha1(msg.encode()).digest(), "big")
    return pow(h, d, n)

def rsa_verify(msg, sig, e, n):
    h = int.from_bytes(sha1(msg.encode()).digest(), "big")
    return pow(sig, e, n) == h

rsa_pub, rsa_priv = gen_rsa_keys()
server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [rsa_encrypt(m, rsa_pub) for m in txns]
    total_enc = 1
    n, e = rsa_pub
    for c in encrypted_txns:
        total_enc = (total_enc * c) % n
    decrypted_txns = [rsa_decrypt(c, rsa_priv, n) for c in encrypted_txns]
    total_dec = rsa_decrypt(total_enc, rsa_priv, n)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = rsa_sign(summary, rsa_priv, n)
    verify_result = rsa_verify(summary, signature, e, n)
    sig_status = "Signed"
    verification = "Valid" if verify_result else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    response = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(response))
    conn.close()

def print_summary():
    print()
    print("| Seller | Transactions | Encrypted Txns | Decrypted Txns | Total Encrypted | Total Decrypted | Signature Status | Verification |")
    for rec in server_summary:
        print(f"| {rec[0]} | {rec[1]} | {rec[2]} | {rec[3]} | {rec[4]} | {rec[5]} | {rec[6]} | {rec[7]} |")

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54332))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()


Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54332))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()


Variation 16: RSA Homomorphic + Schnorr Signatures + SHA-256:
Server :
import socket
import threading
import pickle
from hashlib import sha256
from random import randint

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gen_rsa_keys():
    p = 89
    q = 97
    n = p * q
    phi = (p-1)*(q-1)
    e = 17
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (n, e), d

def rsa_encrypt(m, pub):
    n, e = pub
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def schnorr_gen(p, q, g):
    x = randint(1, q - 1)
    y = pow(g, x, p)
    return (p, q, g, y), x

def schnorr_sign(msg, p, q, g, x):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = int.from_bytes(sha256((str(r) + msg).encode()).digest(), "big") % q
    s = (k + x * e) % q
    return e, s

def modinv_alt(a, m):
    return modinv(a, m)

def schnorr_verify(msg, sig, p, q, g, y):
    e, s = sig
    rv = (pow(g, s, p) * modinv_alt(pow(y, e, p), p)) % p
    ev = int.from_bytes(sha256((str(rv) + msg).encode()).digest(), "big") % q
    return ev == e

pub, priv = gen_rsa_keys()
p, q, g = 1223, 61, 2
spub, spriv = schnorr_gen(p, q, g)
server_summary = []

def handle_client(conn, addr):
    seller_data = pickle.loads(conn.recv(4096))
    name, txns = seller_data
    encrypted


Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54323))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        name = input("Seller Name: ").strip()
        txns = []
        count = int(input("No. of Transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([name, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted, decrypted, total_enc, total_dec, sig_status, sig, summary_str, ver = resp
        print("\nSummary")
        print("Seller:", name)
        print("Transactions:", txns)
        print("Encrypted:", encrypted)
        print("Decrypted:", decrypted)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", sig)
        print("Signature Status:", sig_status)
        print("Signature Verification:", ver)
        s.close()

if __name__ == "__main__":
    main()


Variation 17: ElGamal + RSA Signatures + MD5
Server :
import socket
import threading
import pickle
from random import randint
from hashlib import md5

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt(m, pub):
    p, g, y = pub
    k = randint(2, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return (a, b)

def elgamal_decrypt(c, priv, pub):
    a, b = c
    p, g, y = pub
    s = pow(a, priv, p)
    s_inv = modinv(s, p)
    return (b * s_inv) % p

def gen_rsa_keys():
    p = 89
    q = 97
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (n, e), d

def rsa_sign(msg, d, n):
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    return pow(h, d, n)

def rsa_verify(msg, sig, e, n):
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    return pow(sig, e, n) == h

p, g = 1223, 2
elgamal_pub, elgamal_priv = generate_elgamal_keys(p, g)
rsa_pub, rsa_priv = gen_rsa_keys()
server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [elgamal_encrypt(amount, elgamal_pub) for amount in txns]
    total_enc = encrypted_txns[0]
    for c in encrypted_txns[1:]:
        total_enc = ((total_enc[0] * c[0]) % p, (total_enc[1] * c[1]) % p)
    decrypted_txns = [elgamal_decrypt(c, elgamal_priv, elgamal_pub) for c in encrypted_txns]
    total_dec = elgamal_decrypt(total_enc, elgamal_priv, elgamal_pub)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = rsa_sign(summary, rsa_priv, rsa_pub[0])
    verify_result = rsa_verify(summary, signature, rsa_pub[1], rsa_pub[0])
    sig_status = "Signed"
    verification = "Valid" if verify_result else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    response = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(response))
    conn.close()

def print_summary():
    print()
    print("| Seller | Txns | Encrypted Txns | Decrypted Txns | Encrypted Total | Decrypted Total | Signature Status | Verification |")
    for rec in server_summary:
        print(f"| {rec[0]} | {rec[1]} | {rec[2]} | {rec[3]} | {rec[4]} | {rec[5]} | {rec[6]} | {rec[7]} |")

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54321))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        choice = input("Choose: ").strip()
        if choice == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif choice == '2':
            print_summary()
        elif choice == '3':
            s.close()
            break

if __name__ == "__main__":
    main()


Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54321))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()


Variation 18: ElGamal + ElGamal Signatures + MD5:
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import md5

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt(m, pub):
    p, g, y = pub
    k = randint(2, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return (a, b)

def elgamal_decrypt(c, priv, pub):
    a, b = c
    p, g, _ = pub
    s = pow(a, priv, p)
    s_inv = modinv(s, p)
    return (b * s_inv) % p

def elgamal_sign(msg, p, g, x):
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    while True:
        k = randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(msg, sig, p, g, y):
    r, s = sig
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

p, g = 1223, 2
pub, priv = generate_elgamal_keys(p, g)
server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [elgamal_encrypt(m, pub) for m in txns]
    total_enc = encrypted_txns[0]
    for c in encrypted_txns[1:]:
        total_enc = ((total_enc[0] * c[0]) % p, (total_enc[1] * c[1]) % p)
    decrypted_txns = [elgamal_decrypt(c, priv, pub) for c in encrypted_txns]
    total_dec = elgamal_decrypt(total_enc, priv, pub)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = elgamal_sign(summary, p, g, priv)
    verify_result = elgamal_verify(summary, signature, p, g, pub[2])
    sig_status = "Signed"
    verification = "Valid" if verify_result else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    response = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(response))
    conn.close()

def print_summary():
    print()
    for rec in server_summary:
        print(rec[:-1])

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54321))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()

Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54321))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, sig, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", sig)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()


Variation 19: Paillier + Schnorr Signatures + MD5
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import md5

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_paillier_keys():
    p = 53
    q = 59
    n = p * q
    nsq = n * n
    g = n + 1

    def l(x):
        return (x - 1)//n

    lam = (p -1)*(q -1)
    mu = modinv(l(pow(g, lam, nsq)), n)

    return (n, g, nsq, lam, mu)

def paillier_encrypt(m, pub):
    n, g, nsq, lam, mu = pub
    while True:
        r = randint(1, n - 1)
        if gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(c, priv):
    n, g, nsq, lam, mu = priv
    def l(x):
        return (x -1)//n
    x = pow(c, lam, nsq)
    return (l(x) * mu) % n

def schnorr_gen(p, q, g):
    x = randint(1, q -1)
    y = pow(g, x, p)
    return (p, q, g, y), x

def schnorr_sign(msg, p, q, g, x):
    k = randint(1, q -1)
    r = pow(g, k, p)
    e = int.from_bytes(md5((str(r) + msg).encode()).digest(), "big") % q
    s = (k + x * e) % q
    return e, s

def modinv_alt(a,m):
    return modinv(a,m)

def schnorr_verify(msg, sig, p, q, g, y):
    e, s = sig
    rv = (pow(g, s, p) * modinv_alt(pow(y, e, p), p)) % p
    ev = int.from_bytes(md5((str(rv) + msg).encode()).digest(), "big") % q
    return ev == e

p_val, q_val, g_val = 1223, 61, 2
spub, spriv = schnorr_gen(p_val, q_val, g_val)
pub = generate_paillier_keys()
priv = pub

server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [paillier_encrypt(m, pub) for m in txns]
    total_enc = 1
    n = pub[0]
    nsq = pub[2]
    for c in encrypted_txns:
        total_enc = (total_enc * c) % nsq
    decrypted_txns = [paillier_decrypt(c, priv) for c in encrypted_txns]
    total_dec = paillier_decrypt(total_enc, priv)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    e_s, s_s = schnorr_sign(summary, p_val, q_val, g_val, spriv)
    sig_status = "Signed"
    ver = "Valid" if schnorr_verify(summary, (e_s, s_s), p_val, q_val, g_val, spub[3]) else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, ver, (e_s, s_s)])
    data = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, (e_s, s_s), summary, ver]
    conn.sendall(pickle.dumps(data))
    conn.close()

def print_summary():
    print()
    for rec in server_summary:
        print(rec[:-1])

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54324))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()

Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54324))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, sig, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", sig)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()

Variation 20: Paillier + ElGamal Signatures + MD5
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import md5

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_paillier_keys():
    p = 53
    q = 59
    n = p * q
    nsq = n * n
    g = n + 1

    def l(x):
        return (x - 1)//n

    lam = (p - 1)*(q - 1)
    mu = modinv(l(pow(g, lam, nsq)), n)

    return (n, g, nsq, lam, mu)

def paillier_encrypt(m, pub):
    n, g, nsq, lam, mu = pub
    while True:
        r = randint(1, n - 1)
        if gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(c, priv):
    n, g, nsq, lam, mu = priv
    def l(x):
        return (x -1)//n
    x = pow(c, lam, nsq)
    return (l(x) * mu) % n

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(msg, p, g, x):
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    while True:
        k = randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(msg, sig, p, g, y):
    r, s = sig
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

p_val, g_val = 1223, 2
elgamal_pub, elgamal_priv = generate_elgamal_keys(p_val, g_val)
paillier_pub = generate_paillier_keys()
paillier_priv = paillier_pub

server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [paillier_encrypt(m, paillier_pub) for m in txns]
    total_enc = 1
    nsq = paillier_pub[2]
    for c in encrypted_txns:
        total_enc = (total_enc * c) % nsq
    decrypted_txns = [paillier_decrypt(c, paillier_priv) for c in encrypted_txns]
    total_dec = paillier_decrypt(total_enc, paillier_priv)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = elgamal_sign(summary, p_val, g_val, elgamal_priv)
    verify_result = elgamal_verify(summary, signature, p_val, g_val, elgamal_pub[2])
    sig_status = "Signed"
    verification = "Valid" if verify_result else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    response = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(response))
    conn.close()

def print_summary():
    print()
    print("| Seller | Transactions | Encrypted Txns | Decrypted Txns | Total Encrypted | Total Decrypted | Signature Status | Verification |")
    for rec in server_summary:
        print(f"| {rec[0]} | {rec[1]} | {rec[2]} | {rec[3]} | {rec[4]} | {rec[5]} | {rec[6]} | {rec[7]} |")

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54325))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()

Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54325))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()

Variation 21: RSA Homomorphic + ElGamal Signatures + MD5
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import md5

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gen_rsa_keys():
    p = 89
    q = 97
    n = p * q
    phi = (p-1)*(q-1)
    e = 17
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (n, e), d

def rsa_encrypt(m, pub):
    n, e = pub
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(msg, p, g, x):
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    while True:
        k = randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(msg, sig, p, g, y):
    r, s = sig
    h = int.from_bytes(md5(msg.encode()).digest(), "big")
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

rsa_pub, rsa_priv = gen_rsa_keys()
p, g = 1223, 2
elgamal_pub, elgamal_priv = generate_elgamal_keys(p, g)
server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [rsa_encrypt(m, rsa_pub) for m in txns]
    total_enc = 1
    n, e = rsa_pub
    for c in encrypted_txns:
        total_enc = (total_enc * c) % n
    decrypted_txns = [rsa_decrypt(c, rsa_priv, n) for c in encrypted_txns]
    total_dec = rsa_decrypt(total_enc, rsa_priv, n)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = elgamal_sign(summary, p, g, elgamal_priv)
    verify_result = elgamal_verify(summary, signature, p, g, elgamal_pub[2])
    sig_status = "Signed"
    verification = "Valid" if verify_result else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    response = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(response))
    conn.close()

def print_summary():
    print()
    print("| Seller | Transactions | Encrypted Txns | Decrypted Txns | Total Encrypted | Total Decrypted | Signature Status | Verification |")
    for rec in server_summary:
        print(f"| {rec[0]} | {rec[1]} | {rec[2]} | {rec[3]} | {rec[4]} | {rec[5]} | {rec[6]} | {rec[7]} |")

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54326))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()

Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54326))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()

Variation 22: Paillier + ElGamal Signatures + SHA-256
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import sha256

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_paillier_keys():
    p = 53
    q = 59
    n = p * q
    nsq = n * n
    g = n + 1

    def l(x):
        return (x - 1)//n

    lam = (p - 1)*(q - 1)
    mu = modinv(l(pow(g, lam, nsq)), n)

    return (n, g, nsq, lam, mu)

def paillier_encrypt(m, pub):
    n, g, nsq, lam, mu = pub
    while True:
        r = randint(1, n - 1)
        if gcd(r, n) == 1:
            break
    c = (pow(g, m, nsq) * pow(r, n, nsq)) % nsq
    return c

def paillier_decrypt(c, priv):
    n, g, nsq, lam, mu = priv
    def l(x):
        return (x -1)//n
    x = pow(c, lam, nsq)
    return (l(x) * mu) % n

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(msg, p, g, x):
    h = int.from_bytes(sha256(msg.encode()).digest(), "big")
    while True:
        k = randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(msg, sig, p, g, y):
    r, s = sig
    h = int.from_bytes(sha256(msg.encode()).digest(), "big")
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2

p_val, g_val = 1223, 2
elgamal_pub, elgamal_priv = generate_elgamal_keys(p_val, g_val)
paillier_pub = generate_paillier_keys()
paillier_priv = paillier_pub

server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [paillier_encrypt(m, paillier_pub) for m in txns]
    total_enc = 1
    nsq = paillier_pub[2]
    for c in encrypted_txns:
        total_enc = (total_enc * c) % nsq
    decrypted_txns = [paillier_decrypt(c, paillier_priv) for c in encrypted_txns]
    total_dec = paillier_decrypt(total_enc, paillier_priv)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = elgamal_sign(summary, p_val, g_val, elgamal_priv)
    verify = elgamal_verify(summary, signature, p_val, g_val, elgamal_pub[2])
    sig_status = "Signed"
    verification = "Valid" if verify else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    data = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(data))
    conn.close()

def print_summary():
    print()
    for rec in server_summary:
        print(rec[:-1])

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54327))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()

Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54327))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()

Variation 23: RSA Homomorphic + RSA Signatures + SHA-256
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import sha256

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gen_rsa_keys():
    p = 89
    q = 97
    n = p * q
    phi = (p-1)*(q-1)
    e = 17
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (n, e), d

def rsa_encrypt(m, pub):
    n, e = pub
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

def rsa_sign(msg, d, n):
    h = int.from_bytes(sha256(msg.encode()).digest(), "big")
    return pow(h, d, n)

def rsa_verify(msg, sig, e, n):
    h = int.from_bytes(sha256(msg.encode()).digest(), "big")
    return pow(sig, e, n) == h

rsa_pub, rsa_priv = gen_rsa_keys()
server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [rsa_encrypt(m, rsa_pub) for m in txns]
    total_enc = 1
    n, e = rsa_pub
    for c in encrypted_txns:
        total_enc = (total_enc * c) % n
    decrypted_txns = [rsa_decrypt(c, rsa_priv, n) for c in encrypted_txns]
    total_dec = rsa_decrypt(total_enc, rsa_priv, n)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    signature = rsa_sign(summary, rsa_priv, n)
    verify_result = rsa_verify(summary, signature, e, n)
    sig_status = "Signed"
    verification = "Valid" if verify_result else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, verification, signature])
    response = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification]
    conn.sendall(pickle.dumps(response))
    conn.close()

def print_summary():
    print()
    print("| Seller | Transactions | Encrypted Txns | Decrypted Txns | Encrypted Total | Decrypted Total | Signature Status | Verification |")
    for rec in server_summary:
        print(f"| {rec[0]} | {rec[1]} | {rec[2]} | {rec[3]} | {rec[4]} | {rec[5]} | {rec[6]} | {rec[7]} |")

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54328))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()

Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54328))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, signature, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", signature)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()

Variation 24: ElGamal + Schnorr Signatures + SHA-1
Server:
import socket
import threading
import pickle
from random import randint
from hashlib import sha1

def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_elgamal_keys(p, g):
    x = randint(2, p - 2)
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_encrypt(m, pub):
    p, g, y = pub
    k = randint(2, p - 2)
    a = pow(g, k, p)
    b = (m * pow(y, k, p)) % p
    return (a, b)

def elgamal_decrypt(c, priv, pub):
    a, b = c
    p, g, y = pub
    s = pow(a, priv, p)
    s_inv = modinv(s, p)
    return (b * s_inv) % p

def schnorr_gen(p, q, g):
    x = randint(1, q - 1)
    y = pow(g, x, p)
    return (p, q, g, y), x

def schnorr_sign(msg, p, q, g, x):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = int.from_bytes(sha1((str(r) + msg).encode()).digest(), "big") % q
    s = (k + x * e) % q
    return e, s

def modinv_alt(a, m):
    return modinv(a, m)

def schnorr_verify(msg, sig, p, q, g, y):
    e, s = sig
    rv = (pow(g, s, p) * modinv_alt(pow(y, e, p), p)) % p
    ev = int.from_bytes(sha1((str(rv) + msg).encode()).digest(), "big") % q
    return ev == e

p_val, q_val, g_val = 1223, 61, 2
spub, spriv = schnorr_gen(p_val, q_val, g_val)
pub, priv = generate_elgamal_keys(p_val, g_val)

server_summary = []

def handle_client(conn, addr):
    seller_name, txns = pickle.loads(conn.recv(4096))
    encrypted_txns = [elgamal_encrypt(m, pub) for m in txns]
    total_enc = encrypted_txns[0]
    for c in encrypted_txns[1:]:
        total_enc = ((total_enc[0] * c[0]) % p_val, (total_enc[1] * c[1]) % p_val)
    decrypted_txns = [elgamal_decrypt(c, priv, pub) for c in encrypted_txns]
    total_dec = elgamal_decrypt(total_enc, priv, pub)
    summary = f"{seller_name}|{txns}|{encrypted_txns}|{decrypted_txns}|{total_enc}|{total_dec}"
    e_s, s_s = schnorr_sign(summary, p_val, q_val, g_val, spriv)
    sig_status = "Signed"
    ver = "Valid" if schnorr_verify(summary, (e_s, s_s), p_val, q_val, g_val, spub[3]) else "Invalid"
    server_summary.append([seller_name, txns, encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, ver, (e_s, s_s)])
    data = [encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, (e_s, s_s), summary, ver]
    conn.sendall(pickle.dumps(data))
    conn.close()

def print_summary():
    print()
    for rec in server_summary:
        print(rec[:-1])

def main():
    s = socket.socket()
    s.bind(('0.0.0.0', 54329))
    s.listen(5)
    while True:
        print("\n1. Wait for seller\n2. Print summary\n3. Exit")
        op = input("Choose: ").strip()
        if op == '1':
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        elif op == '2':
            print_summary()
        elif op == '3':
            s.close()
            break

if __name__ == "__main__":
    main()


Client:
import socket
import pickle

def main():
    s = socket.socket()
    s.connect(('localhost', 54329))
    print("\n1. Send Transaction\n2. Exit")
    op = input("Choose: ").strip()
    if op == '1':
        seller = input("Seller Name: ").strip()
        txns = []
        count = int(input("Number of transactions: "))
        for i in range(count):
            amt = int(input(f"Transaction {i+1}: "))
            txns.append(amt)
        s.sendall(pickle.dumps([seller, txns]))
        resp = pickle.loads(s.recv(4096))
        encrypted_txns, decrypted_txns, total_enc, total_dec, sig_status, sig, summary, verification = resp
        print("\nTransaction Summary")
        print("Seller:", seller)
        print("Transactions:", txns)
        print("Encrypted Transactions:", encrypted_txns)
        print("Decrypted Transactions:", decrypted_txns)
        print("Encrypted Total:", total_enc)
        print("Decrypted Total:", total_dec)
        print("Signature:", sig)
        print("Signature Status:", sig_status)
        print("Signature Verification:", verification)
    s.close()

if __name__ == "__main__":
    main()
