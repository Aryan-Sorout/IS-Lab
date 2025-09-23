#!/usr/bin/env python3
"""
MediSecure - Simple prototype for the lab assignment
Features:
 - AES-256-CBC encryption with PKCS7 padding
 - RSA-2048 signing/verifying (SHA512)
 - SHA512 hashing
 - Role-based menu: Patient / Doctor / Auditor
 - File-based storage in ./storage/
 - Simple simulated AES key exchange (should be replaced with proper key exchange in prod)
Dependencies: pycryptodome
    pip install pycryptodome
"""

import os
import json
import base64
import hashlib
from datetime import datetime
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad

STORAGE_DIR = "storage"
KEYS_DIR = "keys"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# ---------- Utilities ----------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

# ---------- Crypto primitives ----------
def generate_rsa_keypair(name: str, passphrase: str=None):
    """Generates RSA keypair and stores in KEYS_DIR with optional passphrase for private key"""
    key = RSA.generate(2048)
    priv_path = os.path.join(KEYS_DIR, f"{name}_priv.pem")
    pub_path = os.path.join(KEYS_DIR, f"{name}_pub.pem")
    if passphrase:
        with open(priv_path, "wb") as f:
            f.write(key.export_key(passphrase=passphrase, pkcs=8))
    else:
        with open(priv_path, "wb") as f:
            f.write(key.export_key())
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"RSA keypair saved: {priv_path}, {pub_path}")

def load_rsa_private(name: str, passphrase: str=None):
    path = os.path.join(KEYS_DIR, f"{name}_priv.pem")
    if not os.path.exists(path):
        raise FileNotFoundError("Private key not found for " + name)
    data = open(path, "rb").read()
    return RSA.import_key(data, passphrase=passphrase)

def load_rsa_public(name: str):
    path = os.path.join(KEYS_DIR, f"{name}_pub.pem")
    if not os.path.exists(path):
        raise FileNotFoundError("Public key not found for " + name)
    return RSA.import_key(open(path, "rb").read())

def aes_encrypt(plaintext: bytes, key: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv, ct

def aes_decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return pt

def rsa_sign(private_key, message_bytes: bytes):
    h = hashlib.sha512(message_bytes).digest()
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hashlib.sha512(message_bytes))
    # pkcs1_15 requires Crypto.Hash object, but pkcs1_15.sign accepts object with .digest? we'll create Crypto.Hash
    # For compatibility use Crypto.Hash.SHA512 below:
    # (We handle properly below where this function is used.)

def rsa_sign_sha512(private_key, message_bytes: bytes):
    # Proper sign using Crypto.Hash.SHA512
    from Crypto.Hash import SHA512
    h = SHA512.new(message_bytes)
    signer = pkcs1_15.new(private_key)
    return signer.sign(h)

def rsa_verify_sha512(public_key, message_bytes: bytes, signature: bytes):
    from Crypto.Hash import SHA512
    h = SHA512.new(message_bytes)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def sha512_hex(data: bytes):
    return hashlib.sha512(data).hexdigest()

# ---------- Storage layout ----------
# Each record is stored as a JSON file named record_<timestamp>_<random>.json containing:
# { patient_id, filename_original, ciphertext_b64, iv_b64, aes_key_b64 (encrypted-simulated), signature_b64, hash_hex, timestamp, uploaded_by }
#
# NOTE: In production, never store AES keys in plain text. Here we simulate secure key exchange by storing AES key
# encrypted with doctor's public key or storing in-memory. The sample code below stores AES key encrypted with RSA public key
# (i.e., patient encrypts AES key with doctor's public key so only the doctor can decrypt it).

def list_records():
    files = sorted([f for f in os.listdir(STORAGE_DIR) if f.endswith(".json")])
    return files

def store_record(metadata: dict):
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    fname = f"record_{ts}.json"
    path = os.path.join(STORAGE_DIR, fname)
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)
    return path

def load_record_by_filename(filename):
    path = os.path.join(STORAGE_DIR, filename)
    with open(path, "r") as f:
        return json.load(f)

# ---------- Role actions ----------
def patient_flow(patient_id: str):
    print("\n--- Patient Menu ---")
    print("1. Generate RSA keypair for yourself (patient) (if not already)")
    print("2. Upload & encrypt a file")
    print("3. View my uploaded records (names, timestamps, hashes)")
    print("0. Back")
    choice = input("Choice: ").strip()
    if choice == "1":
        passphrase = getpass("Enter passphrase for private key (or blank): ")
        generate_rsa_keypair(patient_id, passphrase if passphrase else None)
    elif choice == "2":
        filepath = input("Path of local file to upload: ").strip()
        if not os.path.exists(filepath):
            print("File not found.")
            return
        # read file
        with open(filepath, "rb") as f:
            data = f.read()
        # generate AES key and encrypt
        aes_key = get_random_bytes(32)  # AES-256
        iv, ciphertext = aes_encrypt(data, aes_key)
        # compute SHA512 of ciphertext for integrity
        hash_hex = sha512_hex(ciphertext)
        # sign the ciphertext hash with patient's RSA private key
        try:
            priv = load_rsa_private(patient_id, passphrase=None)
        except Exception as e:
            print("Load private key failed. Make sure you generated keys and the private key is available (no passphrase support in this quick flow).", e)
            return
        signature = rsa_sign_sha512(priv, ciphertext)  # sign ciphertext
        # Simulate secure AES key exchange: encrypt AES key with doctor's public key (doctor must exist)
        doctor_name = input("Doctor username to share key with (e.g., doctor1): ").strip()
        try:
            doc_pub = load_rsa_public(doctor_name)
            # To encrypt small data with RSA, use OAEP (using Crypto.Cipher.PKCS1_OAEP)
            from Crypto.Cipher import PKCS1_OAEP
            cipher_rsa = PKCS1_OAEP.new(doc_pub)
            enc_aes_key = cipher_rsa.encrypt(aes_key)
            enc_key_b64 = b64(enc_aes_key)
        except Exception as e:
            print("Doctor public key not found or RSA OAEP not available: cannot exchange AES key securely. Error:", e)
            return
        metadata = {
            "patient_id": patient_id,
            "filename_original": os.path.basename(filepath),
            "ciphertext_b64": b64(ciphertext),
            "iv_b64": b64(iv),
            "aes_key_encrypted_for_doctor_b64": enc_key_b64,
            "signature_b64": b64(signature),
            "hash_sha512_of_ciphertext": hash_hex,
            "timestamp": now_iso(),
            "uploaded_by": patient_id
        }
        path = store_record(metadata)
        print("Record stored at:", path)
        print("Stored hash (SHA512 of ciphertext):", hash_hex)
    elif choice == "3":
        files = list_records()
        for f in files:
            rec = load_record_by_filename(f)
            if rec.get("patient_id") == patient_id:
                print(f"- {f}: {rec.get('filename_original')} uploaded {rec.get('timestamp')} hash={rec.get('hash_sha512_of_ciphertext')}")
    else:
        return

def doctor_flow(doctor_id: str):
    print("\n--- Doctor Menu ---")
    print("1. Generate RSA keypair for yourself (doctor) (if not already)")
    print("2. List records")
    print("3. Decrypt a record (requires AES key shared)")
    print("4. Verify RSA signature (patient signature)")
    print("0. Back")
    choice = input("Choice: ").strip()
    if choice == "1":
        passphrase = getpass("Enter passphrase for private key (or blank): ")
        generate_rsa_keypair(doctor_id, passphrase if passphrase else None)
    elif choice == "2":
        files = list_records()
        for f in files:
            rec = load_record_by_filename(f)
            print(f"- {f}: patient={rec.get('patient_id')}, file={rec.get('filename_original')}, ts={rec.get('timestamp')}")
    elif choice == "3":
        fn = input("Enter record filename (e.g., record_...json): ").strip()
        if not os.path.exists(os.path.join(STORAGE_DIR, fn)):
            print("Record not found.")
            return
        rec = load_record_by_filename(fn)
        # decrypt AES key using doctor's private key
        try:
            priv = load_rsa_private(doctor_id, passphrase=None)
        except Exception as e:
            print("Load doctor's private key failed. Make sure doctor's private key exists (no passphrase in this quick flow).", e)
            return
        try:
            from Crypto.Cipher import PKCS1_OAEP
            cipher_rsa = PKCS1_OAEP.new(priv)
            enc_key = ub64(rec["aes_key_encrypted_for_doctor_b64"])
            aes_key = cipher_rsa.decrypt(enc_key)
        except Exception as e:
            print("Failed to decrypt AES key; maybe wrong doctor or key not shared. Err:", e)
            return
        iv = ub64(rec["iv_b64"])
        ct = ub64(rec["ciphertext_b64"])
        try:
            plaintext = aes_decrypt(iv, ct, aes_key)
        except Exception as e:
            print("AES decryption failed:", e)
            return
        # Write decrypted file to disk
        outname = f"decrypted_{rec['filename_original']}"
        with open(outname, "wb") as f:
            f.write(plaintext)
        print("Decrypted file saved to", outname)
        # compute hash and compare
        recomputed_hash = sha512_hex(ct)
        print("Stored hash:", rec.get("hash_sha512_of_ciphertext"))
        print("Recomputed hash:", recomputed_hash)
        print("Hash match:", recomputed_hash == rec.get("hash_sha512_of_ciphertext"))
    elif choice == "4":
        fn = input("Enter record filename to verify signature: ").strip()
        if not os.path.exists(os.path.join(STORAGE_DIR, fn)):
            print("Record not found.")
            return
        rec = load_record_by_filename(fn)
        # load patient's public key
        patient = rec.get("patient_id")
        try:
            pat_pub = load_rsa_public(patient)
        except Exception as e:
            print("Patient public key not found. Error:", e)
            return
        ct = ub64(rec["ciphertext_b64"])
        sig = ub64(rec["signature_b64"])
        ok = rsa_verify_sha512(pat_pub, ct, sig)
        print("Signature verification result:", ok)
    else:
        return

def auditor_flow():
    print("\n--- Auditor Menu ---")
    print("1. List records (only metadata and hashes)")
    print("2. Verify signature on a stored record (audit)")
    print("0. Back")
    choice = input("Choice: ").strip()
    if choice == "1":
        files = list_records()
        for f in files:
            rec = load_record_by_filename(f)
            print(f"- {f}: patient={rec.get('patient_id')}, file={rec.get('filename_original')}, ts={rec.get('timestamp')}, hash={rec.get('hash_sha512_of_ciphertext')}")
    elif choice == "2":
        fn = input("Enter record filename to verify signature: ").strip()
        if not os.path.exists(os.path.join(STORAGE_DIR, fn)):
            print("Record not found.")
            return
        rec = load_record_by_filename(fn)
        pat = rec.get("patient_id")
        try:
            pub = load_rsa_public(pat)
        except Exception as e:
            print("Patient public key missing:", e)
            return
        ct = ub64(rec["ciphertext_b64"])
        sig = ub64(rec["signature_b64"])
        ok = rsa_verify_sha512(pub, ct, sig)
        print("Signature valid:", ok)
    else:
        return

# ---------- Main menu ----------
def main_menu():
    print("=== MediSecure (prototype) ===")
    print("Roles: patient, doctor, auditor")
    while True:
        print("\nSelect role or action:")
        print("1. Login as Patient")
        print("2. Login as Doctor")
        print("3. Login as Auditor")
        print("4. Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            pid = input("Enter patient username (e.g., patient1): ").strip()
            patient_flow(pid)
        elif choice == "2":
            did = input("Enter doctor username (e.g., doctor1): ").strip()
            doctor_flow(did)
        elif choice == "3":
            auditor_flow()
        elif choice == "4":
            print("Bye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    print("MediSecure prototype starting.")
    main_menu()
