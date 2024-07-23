# Crypto Project

## Introduction
This project implements a secure communication system using symmetric encryption. The system encrypts messages on one end and sends them via SMS with the decryption key. The recipient uses the key to decrypt the message.

## Features
- Encrypt and decrypt messages using AES symmetric encryption.
- Send encrypted messages and decryption keys via SMS using the Twilio API.
- Web-based user interface built with Flask.

## Technologies
- **Python**: Programming language used.
- **Flask**: Web framework.
- **pycryptodome**: Library for cryptographic functions.
- **Twilio**: API for sending SMS.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/crypto_project.git
   cd crypto_project
