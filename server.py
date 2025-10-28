# gateway_server.py
import socket, threading, json
from Crypto.Util import number
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import inverse, GCD

# ----------- Paillier Implementation -----------
class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n_sq = n * n

class PaillierPrivateKey:
    def __init__(self, public_key, lam, mu):
        self.public_key = public_key
        self.lam = lam
        self.mu = mu

def l_function(u, n): return (u - 1) // n

def generate_paillier_keypair(bits=512):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    n = p * q
    lam = (p - 1) * (q - 1) // number.GCD(p - 1, q - 1)
    g = n + 1
    n_sq = n * n
    x = pow(g, lam, n_sq)
    L = l_function(x, n)
    mu = inverse(L, n)
    pub = PaillierPublicKey(n, g)
    priv = PaillierPrivateKey(pub, lam, mu)
    return pub, priv

def paillier_decrypt(priv, c):
    n = priv.public_key.n
    n_sq = priv.public_key.n_sq
    x = pow(c, priv.lam, n_sq)
    L = l_function(x, n)
    return (L * priv.mu) % n

def paillier_homomorphic_add(pub, c1, c2):
    return (c1 * c2) % pub.n_sq

# ----------- Server -----------
HOST = '127.0.0.1'
PORT = 65432

class GatewayServer:
    def __init__(self, expected_sellers=2):
        self.expected_sellers = expected_sellers
        self.pub, self.priv = generate_paillier_keypair()
        self.rsa_key = RSA.generate(2048)
        self.rsa_pub = self.rsa_key.publickey()
        self.seller_data = {}
        self.client_sockets = {}
        self.verifications = {}
        self.lock = threading.Lock()

    def start(self):
        print("[Gateway] Starting server...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[Gateway] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()

    def handle_client(self, conn):
        try:
            msg = json.loads(conn.recv(65536).decode())
            if msg['type'] == 'HELLO':
                seller = msg['seller']
                print(f"[Gateway] Connected with {seller}")
                self.client_sockets[seller] = conn
                # send Paillier pubkey
                reply = {'type': 'PUBKEY', 'n': str(self.pub.n), 'g': str(self.pub.g)}
                conn.sendall(json.dumps(reply).encode())

                # receive transactions
                data = json.loads(conn.recv(65536).decode())
                if data['type'] == 'TRANSACTIONS':
                    ciphers = [int(c) for c in data['ciphers']]
                    decrypted = [paillier_decrypt(self.priv, c) for c in ciphers]
                    total_cipher = 1
                    for c in ciphers:
                        total_cipher = paillier_homomorphic_add(self.pub, total_cipher, c)
                    total_dec = paillier_decrypt(self.priv, total_cipher)
                    with self.lock:
                        self.seller_data[seller] = {
                            'ciphertexts': [str(c) for c in ciphers],
                            'decrypted': decrypted,
                            'total_cipher': str(total_cipher),
                            'total_decrypted': total_dec
                        }
                    print(f"[Gateway] Seller {seller} total decrypted = {total_dec}")

                    if len(self.seller_data) == self.expected_sellers:
                        self.send_signed_summary()

                # receive verification
                verify_msg = json.loads(conn.recv(65536).decode())
                if verify_msg['type'] == 'VERIFICATION':
                    seller = verify_msg['seller']
                    result = verify_msg['result']
                    with self.lock:
                        self.verifications[seller] = result
                    if len(self.verifications) == self.expected_sellers:
                        self.display_summary()

        except Exception as e:
            print("[Gateway] Error:", e)
            conn.close()

    def build_summary(self):
        data = {'sellers': []}
        for seller, d in self.seller_data.items():
            data['sellers'].append({
                'seller_name': seller,
                'individual_decrypted': d['decrypted'],
                'individual_encrypted': d['ciphertexts'],
                'total_encrypted': d['total_cipher'],
                'total_decrypted': d['total_decrypted']
            })
        return json.dumps(data, sort_keys=True)

    def sign_summary(self, summary):
        h = SHA256.new(summary.encode())
        return pkcs1_15.new(self.rsa_key).sign(h)

    def send_signed_summary(self):
        summary = self.build_summary()
        sig = self.sign_summary(summary)
        payload = {
            'type': 'SIGNED_SUMMARY',
            'summary': summary,
            'signature': sig.hex(),
            'rsa_pub_n': str(self.rsa_pub.n),
            'rsa_pub_e': str(self.rsa_pub.e)
        }
        for s, sock in self.client_sockets.items():
            sock.sendall(json.dumps(payload).encode())

    def display_summary(self):
        print("\n=== FINAL SUMMARY ===")
        for s, d in self.seller_data.items():
            print(f"\nSeller: {s}")
            print("  Transactions:", d['decrypted'])
            print("  Total:", d['total_decrypted'])
            print("  Signature Verified:", self.verifications[s])
        print("=======================")

if __name__ == "__main__":
    server = GatewayServer(expected_sellers=2)
    server.start()
