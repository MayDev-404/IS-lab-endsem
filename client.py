# seller_client.py
import socket, json, sys
from Crypto.Util import number
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import GCD

# -------- Paillier functions --------
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n_sq = n * n

def paillier_encrypt(pub, m):
    n = pub.n
    while True:
        r = random.StrongRandom().randint(1, n - 1)
        if GCD(r, n) == 1:
            break
    return (pow(pub.g, m, pub.n_sq) * pow(r, n, pub.n_sq)) % pub.n_sq

# -------- Client --------
HOST = '127.0.0.1'
PORT = 65432

def main():
    if len(sys.argv) < 2:
        print("Usage: python seller_client.py <SellerName>")
        return

    seller = sys.argv[1]
    transactions = [random.randint(10, 300) for _ in range(2)]
    print(f"[{seller}] Transactions:", transactions)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    s.sendall(json.dumps({'type': 'HELLO', 'seller': seller}).encode())
    msg = json.loads(s.recv(65536).decode())
    n, g = int(msg['n']), int(msg['g'])
    pub = PaillierPublicKey(n, g)

    ciphers = [str(paillier_encrypt(pub, amt)) for amt in transactions]
    s.sendall(json.dumps({'type': 'TRANSACTIONS', 'seller': seller, 'ciphers': ciphers}).encode())

    print(f"[{seller}] Sent encrypted transactions.")

    env = json.loads(s.recv(2000000).decode())
    summary = env['summary']
    signature = bytes.fromhex(env['signature'])
    rsa_pub = RSA.construct((int(env['rsa_pub_n']), int(env['rsa_pub_e'])))
    h = SHA256.new(summary.encode())

    try:
        pkcs1_15.new(rsa_pub).verify(h, signature)
        verified = True
        print(f"[{seller}] Signature verification SUCCESS ✅")
    except:
        verified = False
        print(f"[{seller}] Signature verification FAILED ❌")

    s.sendall(json.dumps({'type': 'VERIFICATION', 'seller': seller, 'result': verified}).encode())
    s.close()

if __name__ == "__main__":
    main()
