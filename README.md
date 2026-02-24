# 🔐 Secure Chat Crypto Demo

A web-based secure messaging application built with Flask that demonstrates core cryptography concepts and real-world security attacks.

This project focuses on both **secure communication** and **common vulnerabilities** in modern systems.

---

## 🚀 Features

### ✅ Secure Messaging
- Elliptic Curve Diffie-Hellman (ECDH) key exchange
- AES-CBC encryption with PKCS#7 padding
- HMAC-SHA256 for integrity and authentication
- Encrypted communication between users (Alice & Bob)

### 🔓 Security Attack Demonstrations
- **Message Injection Attack**
  - Inject fake messages into inbox
  - Detect integrity violations

- **Dictionary Attack**
  - Crack weak passwords using common passwords
  - Demonstrates poor password security

- **Phishing Attack**
  - Fake login page simulation
  - Shows how credentials can be stolen

- **Denial of Service (DoS)**
  - Flood inbox with junk messages
  - Demonstrates availability attacks

---

## 🧠 Concepts Covered

- ECDH Key Exchange
- AES Encryption (CBC Mode)
- HMAC Authentication
- PBKDF2 Key Derivation
- Cybersecurity Attacks:
  - Dictionary attacks
  - Injection attacks
  - Phishing
  - DoS

---

## 🛠️ Tech Stack

- Python (Flask)
- Cryptography library
- HTML / CSS

---

## 📁 Project Structure

```
project/
│── app.py
│── crypto_utils.py
│── templates/
│   ├── index.html
│   ├── dictionary_demo.html
│   ├── phishing_demo.html
│── static/
│   └── style.css
```

---

## ▶️ How to Run

### 1. Install dependencies
```
pip install flask cryptography
```

### 2. Run the app
```
python app.py
```

### 3. Open in browser
```
http://127.0.0.1:5000
```

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.

Some parts are intentionally insecure (e.g., weak passwords, low iterations) to demonstrate real-world attacks.

---

## 👤 Author

- Hussain Alibrahim

---

## 🌟 Notes

This project demonstrates both:
- How secure systems are built
- How they can fail if implemented incorrectly
