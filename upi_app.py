import requests
from flask import Flask, request, jsonify
import pqc_shield

BANK, ME = "http://127.0.0.1:5001", "aarya@pqbank"
STATE = {"shield": True}
client = pqc_shield.ClientShield()
pqc_shield.install(BANK, client, enabled=lambda: STATE["shield"])   # <- the only PQC line

app = Flask(__name__, static_folder="static", static_url_path="")
relay = lambda r: (jsonify(r.json()), r.status_code)

@app.get("/")
def home(): return app.send_static_file("index.html")

@app.get("/api/me")
def me():
    a = requests.get(f"{BANK}/api/account/{ME}", timeout=10).json()
    a.update(shield=STATE["shield"], device_id=client.device_id)
    return jsonify(a)

@app.get("/api/users")
def users(): return relay(requests.get(f"{BANK}/api/users", timeout=10))

@app.post("/api/pay")
def pay():
    d = request.get_json()
    return relay(requests.post(BANK + "/api/pay_plain", timeout=60,
                 json={"from": ME, "to": d["to"], "amount": d["amount"], "pin": d["pin"]}))

@app.post("/api/deposit")
def deposit():
    return relay(requests.post(BANK + "/api/deposit", json={"upi": ME, "amount": request.get_json()["amount"]}, timeout=10))

@app.post("/api/mode")
def mode():
    STATE["shield"] = bool(request.get_json()["on"]); return jsonify(shield=STATE["shield"])

@app.get("/api/wire")
def wire(): return relay(requests.get(f"{BANK}/api/wire", timeout=10))

if __name__ == "__main__":
    app.run(port=5000)
