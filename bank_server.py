import sqlite3, hashlib, os, time
from flask import Flask, request, jsonify
from pqc_shield import ServerShield, b64, unb64

app, DB, shield, WIRE = Flask(__name__), "bank.db", ServerShield(), []

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def hp(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100_000).hex()

def init():
    with db() as c:
        c.executescript("""
        create table if not exists accounts(upi text primary key, name text, salt blob, pin_hash text, balance real);
        create table if not exists devices(device_id text primary key, upi text, pk text);
        create table if not exists txns(id integer primary key autoincrement, ts real, frm text, to_upi text, amount real, status text);""")
        if not c.execute("select 1 from accounts").fetchone():
            for upi, name, pin, bal in [("aarya@pqbank", "Aarya", "1234", 5000), ("ravi@pqbank", "Ravi", "4321", 1000), ("meera@pqbank", "Meera", "1111", 2500)]:
                salt = os.urandom(16)
                c.execute("insert into accounts values(?,?,?,?,?)", (upi, name, salt, hp(pin, salt), bal))

def log(kind, visible):
    WIRE.insert(0, {"t": time.time(), "kind": kind, "visible": visible}); del WIRE[10:]

def transfer(frm, to, amt, pin):
    with db() as c:
        a = c.execute("select * from accounts where upi=?", (frm,)).fetchone()
        b = c.execute("select * from accounts where upi=?", (to,)).fetchone()
        if not a or not b or frm == to: return False, "Invalid UPI ID"
        if amt <= 0: return False, "Invalid amount"
        if hp(str(pin), a["salt"]) != a["pin_hash"]: return False, "Wrong PIN"
        if a["balance"] < amt: return False, "Insufficient balance"
        c.execute("update accounts set balance=balance-? where upi=?", (amt, frm))
        c.execute("update accounts set balance=balance+? where upi=?", (amt, to))
        c.execute("insert into txns(ts,frm,to_upi,amount,status) values(?,?,?,?,?)", (time.time(), frm, to, amt, "SUCCESS"))
    return True, "Payment successful"

@app.get("/pqc/info")
def info(): return jsonify(kem_ek=b64(shield.ek), alg="ML-KEM-768 / ML-DSA-65")

@app.post("/api/register")
def register():
    d = request.get_json()
    with db() as c: c.execute("insert or replace into devices values(?,?,?)", (d["device_id"], d["upi"], d["pk"]))
    return jsonify(ok=True)

@app.get("/api/users")
def users(): return jsonify([dict(r) for r in db().execute("select upi,name from accounts")])

@app.get("/api/account/<upi>")
def account(upi):
    c = db(); a = c.execute("select * from accounts where upi=?", (upi,)).fetchone()
    if not a: return jsonify(ok=False), 404
    tx = [dict(r) for r in c.execute("select ts,frm,to_upi,amount,status from txns where frm=? or to_upi=? order by id desc limit 15", (upi, upi))]
    return jsonify(name=a["name"], upi=upi, balance=a["balance"], txns=tx)

@app.post("/api/deposit")
def deposit():
    d = request.get_json()
    try: amt = float(d["amount"])
    except Exception: return jsonify(ok=False, msg="Invalid amount"), 400
    if amt <= 0: return jsonify(ok=False, msg="Invalid amount"), 400
    with db() as c:
        if not c.execute("select 1 from accounts where upi=?", (d["upi"],)).fetchone(): return jsonify(ok=False, msg="Unknown account"), 404
        c.execute("update accounts set balance=balance+? where upi=?", (amt, d["upi"]))
        c.execute("insert into txns(ts,frm,to_upi,amount,status) values(?,?,?,?,?)", (time.time(), "BANK-DEPOSIT", d["upi"], amt, "SUCCESS"))
    return jsonify(ok=True, msg=f"Deposited ₹{amt:.2f}")

@app.post("/api/pay_plain")      # legacy path: PIN travels as-is
def pay_plain():
    d = request.get_json(); log("UNSHIELDED", d)
    try: ok, msg = transfer(d["from"], d["to"], float(d["amount"]), d["pin"])
    except Exception: ok, msg = False, "Bad request"
    return jsonify(ok=ok, msg=msg), (200 if ok else 400)

@app.post("/api/pay_secure")     # PQC path
def pay_secure():
    env = request.get_json()
    dev = db().execute("select * from devices where device_id=?", (env.get("device_id"),)).fetchone()
    if not dev: return jsonify(ok=False, msg="Unknown device"), 403
    log("PQC-SHIELDED", {k: (f"{v[:32]}… ({len(v)} chars)" if len(v) > 40 else v) for k, v in env.items()})
    try: p = shield.open(env, unb64(dev["pk"]))
    except Exception as e: return jsonify(ok=False, msg=f"Rejected: {e}"), 400
    if p["from"] != dev["upi"]: return jsonify(ok=False, msg="Device not bound to this account"), 403
    try: ok, msg = transfer(p["from"], p["to"], float(p["amount"]), p["pin"])
    except Exception: ok, msg = False, "Bad request"
    return jsonify(ok=ok, msg=msg), (200 if ok else 400)

@app.get("/api/wire")
def wire(): return jsonify(WIRE)

if __name__ == "__main__":
    init(); app.run(port=5001)
