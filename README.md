# 🔐 GeoEncrypt Pro

GeoEncrypt Pro is a location-bound encryption system that combines **cryptography**, **steganography**, and **geographic verification** to protect sensitive data.

Unlike traditional encryption systems where possession of the key is sufficient, GeoEncrypt Pro ensures that **decryption is only possible at the original encryption location**. Even if encrypted files are stolen, decryption will fail unless the geographic conditions are satisfied.

---

## 🧠 Project Overview

Most encryption systems rely on a single secret key. If that key is exposed, the data is compromised.

GeoEncrypt Pro strengthens this model by:
- Encrypting data using strong symmetric cryptography
- Splitting the encryption key into multiple fragments
- Hiding key fragments across image, audio, and video files
- Binding the encryption to a **cryptographically hashed GPS location**

Decryption requires:
- All key fragments
- The correct ciphertext
- Physical presence at the original encryption location

---

## ⚙️ System Architecture

The system is divided into two main components:

### Frontend
- Collects user data and carrier media
- Requests user permission for GPS access
- Sends encrypted payloads to the backend
- Provides a secure UI for encryption and decryption

### Backend
- Performs encryption and decryption
- Handles key splitting and reconstruction
- Applies steganographic techniques
- Validates geographic authenticity using cryptographic hashes

---

## 🔒 Encryption Workflow

1. User enters sensitive data
2. Browser requests GPS permission
3. Latitude and longitude are captured
4. Data is encrypted using **Fernet (AES-128 + HMAC)**
5. Encryption key is split into three Base64 fragments
6. Key fragments are stored as follows:
   - **Image (PNG)**: LSB steganography with GPS hash and salt
   - **Audio (WAV)**: LSB bit embedding
   - **Video (MP4)**: Byte-level key appending
7. A cryptographic hash of GPS coordinates is generated using:
   - PBKDF2-HMAC-SHA256
   - 100,000 iterations
   - 16-byte random salt
8. Encrypted ciphertext and encoded media files are generated

---

## 🔓 Decryption Workflow

1. User uploads:
   - Ciphertext
   - Encoded image, audio, and video files
2. Browser captures current GPS location
3. Backend extracts:
   - Key fragments
   - Stored GPS hash and salt
4. Current location is hashed and compared using constant-time comparison
5. If location validation passes:
   - Key fragments are reconstructed
   - Ciphertext is decrypted
6. If location validation fails:
   - Decryption is denied

---

## 📍 Location Security Model

- GPS coordinates are **never stored in plaintext**
- Coordinates are hashed using PBKDF2 with a random salt
- Only the hash and salt are embedded in media files
- Location comparison uses constant-time verification to prevent timing attacks

This creates a **cryptographic proof-of-location**, not a tracking system.

---

## 🔐 Security Features

- Fernet symmetric encryption (AES-128 + HMAC)
- Distributed key storage across multiple media formats
- Multi-layer steganography
- Location-bound decryption
- Cryptographically secure random salts
- Base64 padding correction for reliable key reconstruction
- No server-side storage of user locations

---

## 🛠️ Technology Stack

### Frontend
- React.js
- Axios
- HTML, CSS, JavaScript
- Browser Geolocation API

### Backend
- Python
- Flask
- Flask-CORS
- Cryptography (Fernet)
- Stegano (LSB image steganography)
- Wave module (audio processing)
- Hashlib & Secrets (secure hashing and comparison)
- NumPy & OpenCV (video handling)

---

## 📁 Supported Media Formats

| Media Type | Format | Technique |
|----------|--------|----------|
| Image | PNG | LSB steganography + GPS hash |
| Audio | WAV | LSB bit embedding |
| Video | MP4 | Byte-level key embedding |

---

## 🚀 Running the Project

### Backend Setup
```bash
pip install flask flask-cors cryptography stegano opencv-python numpy
python backend.py
