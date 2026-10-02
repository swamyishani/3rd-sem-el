"""PQC Shield: drop-in post-quantum wrapper (ML-KEM-768 + ML-DSA-65 + AES-256-GCM)."""
import os, json, time, base64
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_768 as KEM
from dilithium_py.ml_dsa import ML_DSA_65 as DSA

b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)

def _key(secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"upi-pqc-shield-v1").derive(secret)

class ClientShield:
    """Runs on the phone/UPI-app side. Holds the device's ML-DSA identity key."""
    def __init__(self, keyfile="device_keys.json"):
        if os.path.exists(keyfile):
            d = json.load(open(keyfile))
            self.pk, self.sk, self.device_id = unb64(d["pk"]), unb64(d["sk"]), d["id"]
        else:
            self.pk, self.sk = DSA.keygen()
            self.device_id = os.urandom(6).hex()
            json.dump({"pk": b64(self.pk), "sk": b64(self.sk), "id": self.device_id}, open(keyfile, "w"))

    def seal(self, server_ek, payload):
        secret, kem_ct = KEM.encaps(server_ek)                      # ML-KEM: fresh shared secret
        body = json.dumps({**payload, "ts": time.time(), "jti": os.urandom(8).hex()}).encode()
        nonce = os.urandom(12)
        ct = AESGCM(_key(secret)).encrypt(nonce, body, self.device_id.encode())
        sig = DSA.sign(self.sk, kem_ct + nonce + ct)                # ML-DSA: authenticity
        return {"device_id": self.device_id, "kem_ct": b64(kem_ct),
                "nonce": b64(nonce), "ct": b64(ct), "sig": b64(sig)}

class ServerShield:
    """Runs at the bank/gateway side."""
    def __init__(self):
        self.ek, self.dk = KEM.keygen()
        self.seen = {}

    def open(self, env, device_pk):
        kem_ct, nonce, ct, sig = (unb64(env[k]) for k in ("kem_ct", "nonce", "ct", "sig"))
        if not DSA.verify(device_pk, kem_ct + nonce + ct, sig):
            raise ValueError("bad signature")
        body = AESGCM(_key(KEM.decaps(self.dk, kem_ct))).decrypt(nonce, ct, env["device_id"].encode())
        p = json.loads(body)
        now = time.time()
        if abs(now - p["ts"]) > 60:
            raise ValueError("stale request")
        self.seen = {j: t for j, t in self.seen.items() if now - t < 120}
        if p["jti"] in self.seen:
            raise ValueError("replay detected")
        self.seen[p["jti"]] = now
        return p

def install(bank_url, client, enabled=lambda: True):
    """Wrap requests.post so PIN payments to the bank are sealed. App code is untouched."""
    orig_post, orig_get = requests.post, requests.get
    state = {"registered": False}

    def patched(url, *a, **kw):
        if enabled() and url == bank_url + "/api/pay_plain":
            payload = kw.pop("json")
            if not state["registered"]:
                orig_post(bank_url + "/api/register", timeout=10,
                          json={"device_id": client.device_id, "upi": payload["from"], "pk": b64(client.pk)})
                state["registered"] = True
            ek = unb64(orig_get(bank_url + "/pqc/info", timeout=10).json()["kem_ek"])
            return orig_post(bank_url + "/api/pay_secure", json=client.seal(ek, payload), timeout=60)
        return orig_post(url, *a, **kw)

    requests.post = patched
