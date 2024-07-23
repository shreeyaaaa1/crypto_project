from flask import Flask, request, render_template, flash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from twilio.rest import Client
import os
import base64
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initializing the Flask application
app = Flask(__name__)
# Set a secret key for session management, generated randomly
app.secret_key = os.urandom(24)

# Retrieve Twilio credentials from environment variables for security
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', 'your_account_sid_here').strip()
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', 'your_auth_token_here').strip()
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER', 'your_twilio_number_here').strip()

# Debug output to confirm Twilio credentials are loaded correctly
print(f'TWILIO_ACCOUNT_SID: "{TWILIO_ACCOUNT_SID}"')
print(f'TWILIO_AUTH_TOKEN: "{TWILIO_AUTH_TOKEN}"')
print(f'TWILIO_PHONE_NUMBER: "{TWILIO_PHONE_NUMBER}"')

# Initialize the Twilio client for sending messages
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Function to generate a secure key from a password and salt using PBKDF2
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key from the password
    return key

# Function to encrypt a given message with a password
def encrypt_message(message, password):
    salt = os.urandom(16)  # Generate a random salt
    key = generate_key(password, salt)  # Create a key from the password and salt
    iv = os.urandom(16)  # Generate an initialization vector (IV) for encryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()  # Create an encryptor object
    ct = encryptor.update(message.encode()) + encryptor.finalize()  # Encrypt the message
    # Return the combined salt, IV, and ciphertext encoded in a URL-safe format
    return base64.urlsafe_b64encode(salt + iv + ct).decode()

# Function to decrypt an encrypted message using the provided password
def decrypt_message(encrypted_message, password):
    decoded_data = base64.urlsafe_b64decode(encrypted_message.encode())  # Decode the encrypted message
    salt = decoded_data[:16]  # Extract the salt
    iv = decoded_data[16:32]  # Extract the IV
    ct = decoded_data[32:]  # Extract the ciphertext
    key = generate_key(password, salt)  # Derive the key using the same salt
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()  # Create a decryptor object
    message = decryptor.update(ct) + decryptor.finalize()  # Decrypt the message
    return message.decode()

# Define the main route for the web application
@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = None
    decrypted_message = None

    if request.method == 'POST':  # Handle form submissions
        if 'encrypt' in request.form:
            phone_number = request.form['phone_number']  # Get phone number from form
            message = request.form['message']  # Get the message to encrypt
            password = os.urandom(16).hex()  # Generate a random password for encryption
            encrypted_message = encrypt_message(message, password)  # Encrypt the message
            try:
                # Send the encrypted message and the decryption key via SMS
                client.messages.create(
                    body=f'Your encrypted message is: {encrypted_message}\nYour decryption key is: {password}',
                    from_=TWILIO_PHONE_NUMBER,
                    to=phone_number
                )
                flash('SMS sent successfully!', 'success')  # Notifying user of success
            except Exception as e:
                flash(f'Failed to send SMS: {e}', 'danger')  # Notifying user in case of error
        
        elif 'decrypt' in request.form:
            encrypted_message = request.form['encrypted_message']  # Get the encrypted message from form
            password = request.form['password']  # Get the password for decryption
            try:
                decrypted_message = decrypt_message(encrypted_message, password)  # Decrypt the message
                flash('Message decrypted successfully', 'success')  # Notify user of success
            except Exception as e:
                flash(f'Failed to decrypt message: {e}', 'danger')  # Notify user of error

    return render_template('index.html', encrypted_message=encrypted_message, decrypted_message=decrypted_message)  # Render the main template

# Run the Flask application in debug mode
if __name__ == '__main__':
    app.run(debug=True)
