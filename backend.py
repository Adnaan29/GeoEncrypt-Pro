from flask import Flask, request, jsonify, send_from_directory
from cryptography.fernet import Fernet
from flask_cors import CORS
from stegano import lsb
import os
import base64
import wave
import hashlib
import secrets
import tempfile
import math

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

### 🔹 ENHANCED GEOLOCATION HANDLING ###
def generate_gps_hash(lat, lon, salt):
    """Generate secure hash of GPS coordinates with salt"""
    coord_str = f"{lat:.6f},{lon:.6f}"
    return hashlib.pbkdf2_hmac('sha256', coord_str.encode(), salt, 100000).hex()

def validate_location(current_lat, current_lon, stored_hash, salt):
    """Verify current location matches stored hash"""
    current_hash = generate_gps_hash(current_lat, current_lon, salt)
    return secrets.compare_digest(current_hash, stored_hash)

def haversine(lat1, lon1, lat2, lon2):
    """Calculate distance between two GPS points in meters"""
    R = 6371e3  # Earth radius in meters
    φ1 = math.radians(lat1)
    φ2 = math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)

    a = math.sin(Δφ/2)**2 + math.cos(φ1)*math.cos(φ2)*math.sin(Δλ/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    return R * c

def validate_gps(lat, lon):
    return -90 <= lat <= 90 and -180 <= lon <= 180

### 🔹 BASE64 PADDING FIX ###
def fix_base64_padding(b64_string):
    """Ensure Base64 string has correct padding."""
    missing_padding = len(b64_string) % 4
    if missing_padding:
        b64_string += "=" * (4 - missing_padding)
    return b64_string

### 🔹 KEY SPLITTING & RECONSTRUCTION ###
def split_key_flexible(key, num_parts=3):
    """Split key into `num_parts` parts using Base64 encoding."""
    key_b64 = base64.urlsafe_b64encode(key).decode()
    key_length = len(key_b64)
    base_size = key_length // num_parts  
    remainder = key_length % num_parts  

    key_parts = []
    start = 0
    for i in range(num_parts):
        extra_byte = 1 if i < remainder else 0  
        end = start + base_size + extra_byte
        key_part = key_b64[start:end].strip()
        key_parts.append(key_part)
        start = end
    
    print(f"🔹 Original Encryption Key (Base64): {key_b64}")  # DEBUG
    print(f"🔹 Split Keys: {key_parts}")  # DEBUG
    return key_parts

def reconstruct_key(parts):
    """Reconstruct key from Base64 encoded parts."""
    try:
        key_b64 = "".join(parts).strip()
        key_b64 = fix_base64_padding(key_b64)
        print(f"🔹 Reconstructed Key (Base64): {key_b64}")  # DEBUG
        reconstructed_key = base64.urlsafe_b64decode(key_b64)
        print(f"🔹 Reconstructed Key (Decoded): {reconstructed_key}")  # DEBUG
        return reconstructed_key
    except Exception as e:
        print("❌ Key reconstruction failed:", str(e))
        return None

### 🔹 SECURE IMAGE STEGANOGRAPHY ###
def hide_key_in_image(input_image, key_part, lat, lon, output_path):
    """Hides key part and hashed GPS data in image."""
    try:
        # Generate secure hash with salt
        salt = secrets.token_bytes(16)
        gps_hash = generate_gps_hash(lat, lon, salt)
        
        # Combine data with delimiters
        combined_data = f"{key_part}|||{gps_hash}|||{base64.urlsafe_b64encode(salt).decode()}"
        
        # Hide data using steganography
        secret_image = lsb.hide(input_image, combined_data)
        secret_image.save(output_path)
        return output_path
    except Exception as e:
        print("❌ Error hiding key part:", str(e))
        return None

def extract_key_from_image(encoded_image):
    """Extracts key part, GPS hash, and salt from image."""
    try:
        extracted_data = lsb.reveal(encoded_image)
        key_part, gps_hash, salt_b64 = extracted_data.split("|||")
        salt = base64.urlsafe_b64decode(salt_b64)
        return key_part.strip(), gps_hash.strip(), salt
    except Exception as e:
        print("❌ Error extracting key part:", str(e))
        return "", "", b""

### 🔹 AUDIO STEGANOGRAPHY ###
def hide_key_in_audio(audio_path, key_part, output_path):
    """Hides a key part in an audio file using LSB on WAV format."""
    try:
        with wave.open(audio_path, "rb") as audio:
            params = audio.getparams()
            frames = bytearray(audio.readframes(audio.getnframes()))

        key_bin = ''.join(format(ord(char), '08b') for char in key_part)
        key_length = len(key_bin)

        if key_length > len(frames):
            print("❌ Error: Key is too large for the audio file.")
            return None

        for i in range(key_length):
            frames[i] = (frames[i] & 0xFE) | int(key_bin[i])
        
        with wave.open(output_path, "wb") as encoded_audio:
            encoded_audio.setparams(params)
            encoded_audio.writeframes(bytes(frames))
        
        return output_path
    except Exception as e:
        print("❌ Error hiding key in audio:", str(e))
        return None

def extract_key_from_audio(audio_path):
    """Extracts a hidden key part from an audio file with correct length."""
    try:
        with wave.open(audio_path, "rb") as encoded_audio:
            frames = list(encoded_audio.readframes(encoded_audio.getnframes()))
        
        key_bin = ''.join(str(frames[i] & 1) for i in range(160))  
        key_part = ''.join(chr(int(key_bin[i:i+8], 2)) for i in range(0, len(key_bin), 8))

        print(f"🔹 Extracted Key from Audio (Binary): {key_bin}")  # DEBUG
        print(f"🔹 Extracted Key from Audio (Decoded): {key_part.strip()}")  # DEBUG
        
        return key_part.strip()
    except Exception as e:
        print("❌ Error extracting key from audio:", str(e))
        return ""

### 🔹 VIDEO STEGANOGRAPHY ###
def hide_key_in_video(video_file, key_part, output_path):
    """Appends key part to end of video file as plain bytes."""
    try:
        temp_path = os.path.join(tempfile.gettempdir(), "video_temp.mp4")
        video_file.save(temp_path)

        with open(temp_path, "rb") as vf:
            video_data = vf.read()
        
        marker = b"==KEYSTART=="
        key_bytes = key_part.encode()

        with open(output_path, "wb") as out_f:
            out_f.write(video_data)
            out_f.write(marker + key_bytes)

        os.remove(temp_path)
        return output_path

    except Exception as e:
        print("❌ Error appending key to video file:", str(e))
        return None

def extract_key_from_video(video_file):
    """Extracts the key part appended at the end of the video file."""
    try:
        temp_path = os.path.join(tempfile.gettempdir(), "video_temp_extract.mp4")
        video_file.save(temp_path)

        with open(temp_path, "rb") as vf:
            video_data = vf.read()

        marker = b"==KEYSTART=="
        if marker in video_data:
            key_part = video_data.split(marker)[-1]
            key_str = key_part.decode(errors='ignore').strip()
            print(f"🔹 Extracted Key from Video: {key_str}")
            os.remove(temp_path)
            return key_str
        else:
            print("❌ No key marker found in video file.")
            os.remove(temp_path)
            return ""

    except Exception as e:
        print("❌ Error extracting key from video file:", str(e))
        return ""

### 🔹 ENCRYPTION ROUTE ###
@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt data and hide key parts with geolocation."""
    # Validate GPS coordinates
    try:
        lat = float(request.form['latitude'])
        lon = float(request.form['longitude'])
        if not validate_gps(lat, lon):
            return jsonify({"error": "Invalid GPS coordinates"}), 400
    except:
        return jsonify({"error": "Valid GPS coordinates required"}), 400

    if 'data' not in request.form:
        return jsonify({"error": "No data provided"}), 400

    data = request.form['data']

    # Generate encryption key
    encryption_key = Fernet.generate_key()
    cipher = Fernet(encryption_key)
    encrypted_data = cipher.encrypt(data.encode()).decode()

    # Split the key
    key_parts = split_key_flexible(encryption_key)

    # Process image with GPS hash
    uploaded_image = request.files.get('image')
    if not uploaded_image:
        return jsonify({"error": "Please upload an image"}), 400
    
    input_image_path = os.path.join(UPLOAD_FOLDER, "uploaded_image.png")
    encoded_image_path = os.path.join(UPLOAD_FOLDER, "encoded_image.png")
    uploaded_image.save(input_image_path)
    
    if hide_key_in_image(input_image_path, key_parts[0], lat, lon, encoded_image_path) is None:
        return jsonify({"error": "Failed to hide key part in image"}), 500

    # Process audio
    uploaded_audio = request.files.get('audio')
    if not uploaded_audio:
        return jsonify({"error": "Please upload an audio file"}), 400

    input_audio_path = os.path.join(UPLOAD_FOLDER, "uploaded_audio.wav")
    encoded_audio_path = os.path.join(UPLOAD_FOLDER, "encoded_audio.wav")
    uploaded_audio.save(input_audio_path)
    
    if hide_key_in_audio(input_audio_path, key_parts[1], encoded_audio_path) is None:
        return jsonify({"error": "Failed to hide key part in audio"}), 500

    # Process video
    uploaded_video = request.files.get('video')
    if not uploaded_video:
        return jsonify({"error": "Please upload a video file"}), 400

    encoded_video_path = os.path.join(UPLOAD_FOLDER, "encoded_video.mp4")
    if hide_key_in_video(uploaded_video, key_parts[2], encoded_video_path) is None:
        return jsonify({"error": "Failed to hide key part in video"}), 500

    return jsonify({
        "ciphertext": encrypted_data,
        "encoded_image": f"http://localhost:5000/download/{os.path.basename(encoded_image_path)}",
        "encoded_audio": f"http://localhost:5000/download/{os.path.basename(encoded_audio_path)}",
        "encoded_video": f"http://localhost:5000/download/{os.path.basename(encoded_video_path)}"
    })

### 🔹 DECRYPTION ROUTE ###
@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt with geolocation validation."""
    # Get current location
    try:
        current_lat = float(request.form['currentLat'])
        current_lon = float(request.form['currentLon'])
    except:
        return jsonify({"error": "Location access required"}), 400

    # Extract data from image
    uploaded_image = request.files.get('encoded_image')
    if not uploaded_image:
        return jsonify({"error": "Encoded image required"}), 400
    
    key_part, stored_hash, salt = extract_key_from_image(uploaded_image)
    if not all([stored_hash, salt]):
        return jsonify({"error": "Invalid security data in media file"}), 400

    # Validate location via hash comparison
    if not validate_location(current_lat, current_lon, stored_hash, salt):
        return jsonify({"error": "Decryption not allowed at this location"}), 403

    # Process ciphertext
    if 'ciphertext' not in request.form:
        return jsonify({"error": "Ciphertext missing"}), 400
    encrypted_data = request.form['ciphertext']

    # Process audio
    uploaded_audio = request.files.get('encoded_audio')
    extracted_audio_key = extract_key_from_audio(uploaded_audio) if uploaded_audio else ""

    # Process video
    uploaded_video = request.files.get('encoded_video')
    extracted_video_key = extract_key_from_video(uploaded_video) if uploaded_video else ""

    extracted_parts = [key_part, extracted_audio_key, extracted_video_key]
    print(f"🔹 Extracted Key Parts: {extracted_parts}")

    reconstructed_key = reconstruct_key(extracted_parts)
    if not reconstructed_key:
        return jsonify({"error": "Failed to reconstruct key"}), 400

    try:
        cipher = Fernet(reconstructed_key)
        decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
        return jsonify({"decrypted_text": decrypted_data})
    except Exception as e:
        print("❌ Decryption failed:", str(e))
        return jsonify({"error": "Decryption failed - possibly corrupted key parts"}), 400

### 🔹 FILE DOWNLOAD ROUTE ###
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)