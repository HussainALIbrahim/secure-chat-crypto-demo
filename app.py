# app.py

import os
from flask import Flask, render_template, request, redirect, url_for, flash

from crypto_utils import (
    generate_ec_keypair,
    derive_shared_key,
    serialize_public_key,
    encrypt_aes_cbc_pkcs7,
    decrypt_aes_cbc_pkcs7,
    compute_hmac,
    verify_hmac,
    derive_key_from_password,
    dictionary_attack,
    b64e,
    b64d,
    COMMON_PASSWORDS,
)

app = Flask(__name__)
app.secret_key = "CHANGE_ME_FOR_REAL_USE"  # for sessions/flash


# =========================
# Simple "in-memory database"
# =========================

USERS = {}  # name -> {private, public, public_pem, inbox: [...]}
MESSAGE_COUNTER = 0


def init_users():
    """Create two demo users with EC keypairs."""
    global USERS
    for name in ("Alice", "Bob"):
        priv, pub = generate_ec_keypair()
        USERS[name] = {
            "private": priv,
            "public": pub,
            "public_pem": serialize_public_key(pub).decode("utf-8"),
            "inbox": [],  # list of message dicts
        }


def derive_conversation_key(user1: str, user2: str) -> bytes:
    """
    Derive a symmetric key for conversation between two users using ECDH.
    ECDH is symmetric, so key(Alice priv, Bob pub) = key(Bob priv, Alice pub).
    """
    priv = USERS[user1]["private"]
    pub = USERS[user2]["public"]
    return derive_shared_key(priv, pub)


# Call once at startup (Flask 3.x removed before_first_request)
init_users()


# =========================
# Routes
# =========================

@app.route("/", methods=["GET"])
def index():
    """
    Main page: compose message, send, and view decrypted inbox.
    """
    selected_user = request.args.get("user", "Alice")
    if selected_user not in USERS:
        selected_user = "Alice"

    inbox_raw = USERS[selected_user]["inbox"]

    decrypted_messages = []
    for msg in inbox_raw:
        sender = msg["sender"]
        receiver = msg["receiver"]

        # --- NEW: if sender/receiver are unknown (e.g., Mallory), mark as injected ---
        if sender not in USERS or receiver not in USERS:
            decrypted_messages.append(
                {
                    "id": msg["id"],
                    "sender": sender,
                    "receiver": receiver,
                    "ciphertext_b64": msg["ciphertext_b64"],
                    "iv_b64": msg["iv_b64"],
                    "hmac_b64": msg["hmac_b64"],
                    "plaintext": (
                        "(untrusted sender – no shared ECDH key; "
                        "possible injected message)"
                    ),
                    "status": "UNTRUSTED SENDER / POSSIBLE INJECTION",
                    "tampered": True,
                }
            )
            continue
        # ---------------------------------------------------------------------------

        # Normal case: both are valid users → derive key and verify HMAC
        key = derive_conversation_key(sender, receiver)
        iv = b64d(msg["iv_b64"])
        ct = b64d(msg["ciphertext_b64"])
        tag = b64d(msg["hmac_b64"])

        data_for_hmac = iv + ct

        try:
            verify_hmac(key, data_for_hmac, tag)
            plaintext = decrypt_aes_cbc_pkcs7(key, iv, ct).decode(
                "utf-8", errors="replace"
            )
            status = "OK (Integrity verified)"
            tampered = False
        except Exception:
            plaintext = (
                "(could not decrypt – integrity check failed; "
                "possible tampering/message injection)"
            )
            status = "INTEGRITY ERROR"
            tampered = True

        decrypted_messages.append(
            {
                "id": msg["id"],
                "sender": sender,
                "receiver": receiver,
                "ciphertext_b64": msg["ciphertext_b64"],
                "iv_b64": msg["iv_b64"],
                "hmac_b64": msg["hmac_b64"],
                "plaintext": plaintext,
                "status": status,
                "tampered": tampered,
            }
        )

    return render_template(
        "index.html",
        users=list(USERS.keys()),
        selected_user=selected_user,
        decrypted_messages=decrypted_messages,
    )


@app.route("/send", methods=["POST"])
def send_message():
    """
    Secure send:
    - ECDH between sender and receiver
    - AES-CBC + PKCS#7
    - HMAC for integrity & authentication
    """
    global MESSAGE_COUNTER

    sender = request.form.get("sender")
    receiver = request.form.get("receiver")
    message = request.form.get("message", "")

    if not sender or not receiver or sender not in USERS or receiver not in USERS:
        flash("Invalid sender or receiver", "error")
        return redirect(url_for("index", user=sender or "Alice"))

    if not message.strip():
        flash("Message is empty", "error")
        return redirect(url_for("index", user=sender))

    # Derive symmetric key for this pair
    key = derive_conversation_key(sender, receiver)

    iv, ciphertext = encrypt_aes_cbc_pkcs7(key, message.encode("utf-8"))
    data_for_hmac = iv + ciphertext
    tag = compute_hmac(key, data_for_hmac)

    MESSAGE_COUNTER += 1
    msg_entry = {
        "id": MESSAGE_COUNTER,
        "sender": sender,
        "receiver": receiver,
        "iv_b64": b64e(iv),
        "ciphertext_b64": b64e(ciphertext),
        "hmac_b64": b64e(tag),
    }

    USERS[receiver]["inbox"].append(msg_entry)
    flash(f"Secure message sent from {sender} to {receiver}.", "success")
    return redirect(url_for("index", user=sender))


# =========================
# Integrity Attack: Message Injection
# =========================

@app.route("/attack/inject", methods=["POST"])
def attack_inject():
    """
    Message injection:
    - Add a fake message to victim inbox with random bytes and random HMAC.
    - Decrypt view will detect integrity failure or unknown sender.
    """
    global MESSAGE_COUNTER

    attacker_name = "Mallory"  # logical attacker identity
    victim = request.form.get("victim")

    if victim not in USERS:
        flash("Invalid victim user", "error")
        return redirect(url_for("index", user="Alice"))

    # Random garbage – will NOT match HMAC with legitimate key
    fake_iv = os.urandom(16)
    fake_ct = os.urandom(48)
    fake_tag = os.urandom(32)

    MESSAGE_COUNTER += 1
    msg_entry = {
        "id": MESSAGE_COUNTER,
        "sender": attacker_name,
        "receiver": victim,
        "iv_b64": b64e(fake_iv),
        "ciphertext_b64": b64e(fake_ct),
        "hmac_b64": b64e(fake_tag),
    }

    USERS[victim]["inbox"].append(msg_entry)
    flash(
        f"Injected a fake message into {victim}'s inbox. "
        f"It should be flagged as untrusted / integrity error when decrypted.",
        "warning",
    )
    return redirect(url_for("index", user=victim))


# =========================
# Confidentiality Attack: Dictionary Attack Demo
# =========================

@app.route("/attack/dictionary-demo", methods=["GET", "POST"])
def dictionary_demo():
    """
    Shows how a weak password can be cracked with a small dictionary.
    This is *separate* from the main ECDH + AES workflow.
    """
    result = None

    if request.method == "POST":
        weak_password = request.form.get("weak_password", "password123")
        secret_message = request.form.get("secret_message", "My bank PIN is 1234.")

        # Honest user encrypts using weak password
        salt = os.urandom(16)
        key = derive_key_from_password(weak_password, salt)
        iv, ct = encrypt_aes_cbc_pkcs7(key, secret_message.encode("utf-8"))

        # Attacker runs dictionary attack
        success, found_pwd, recovered_pt, _ = dictionary_attack(ct, iv, salt)

        if success:
            result = {
                "success": True,
                "original_password": weak_password,
                "found_password": found_pwd,
                "recovered_plaintext": recovered_pt.decode(
                    "utf-8", errors="replace"
                ),
                "ciphertext_b64": b64e(ct),
                "iv_b64": b64e(iv),
                "salt_b64": b64e(salt),
            }
        else:
            result = {
                "success": False,
                "original_password": weak_password,
                "ciphertext_b64": b64e(ct),
                "iv_b64": b64e(iv),
                "salt_b64": b64e(salt),
            }

    return render_template(
        "dictionary_demo.html",
        common_passwords=COMMON_PASSWORDS,
        result=result,
    )


# =========================
# Authentication Attack: Phishing Demo
# =========================

@app.route("/attack/phishing-demo", methods=["GET", "POST"])
def phishing_demo():
    """
    Very simple phishing demo:
    - Shows a "fake login" page that *looks* like a secure messenger login.
    - When user submits, we log that the attacker stole the credentials.
    (DO NOT actually store real passwords here – this is only for demo.)
    """
    stolen = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # In a real attack, attacker would now have these credentials.
        stolen = {"username": username, "password": password}
    return render_template("phishing_demo.html", stolen=stolen)


# =========================
# Availability Attack: DoS-style Flooding
# =========================

@app.route("/attack/dos", methods=["POST"])
def dos_attack():
    """
    DoS demo:
    - Flood a user's inbox with many random messages.
    - The GUI remains simple, but you can explain that large floods
      can slow down the app / consume resources.
    """
    global MESSAGE_COUNTER

    victim = request.form.get("victim")
    count = int(request.form.get("count", 100))

    if victim not in USERS:
        flash("Invalid victim user", "error")
        return redirect(url_for("index", user="Alice"))

    for _ in range(count):
        fake_iv = os.urandom(16)
        fake_ct = os.urandom(48)
        fake_tag = os.urandom(32)
        MESSAGE_COUNTER += 1
        msg_entry = {
            "id": MESSAGE_COUNTER,
            "sender": "FloodBot",
            "receiver": victim,
            "iv_b64": b64e(fake_iv),
            "ciphertext_b64": b64e(fake_ct),
            "hmac_b64": b64e(fake_tag),
        }
        USERS[victim]["inbox"].append(msg_entry)

    flash(f"Flooded {victim}'s inbox with {count} junk messages (DoS demo).", "warning")
    return redirect(url_for("index", user=victim))


if __name__ == "__main__":
    # Run the Flask dev server
    app.run(debug=True)
