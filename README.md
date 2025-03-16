# CBC Padding Oracle Attack Implementation

This repository contains a Python implementation of a CBC (Cipher Block Chaining) Padding Oracle Attack. The attack demonstrates how padding oracle vulnerabilities can be exploited in CBC mode encryption.

## Description

The script performs a padding oracle attack against a web server that exposes an endpoint vulnerable to this type of attack. It can decrypt encrypted content and forge new encrypted messages that will be accepted by the server.

## Prerequisites

- Python 3.x
- Required Python packages:
  ```bash
  pip install requests pycryptodome
  ```

## Usage

Run the script from the command line with the target server's URL as an argument:

```bash
python paddingattack.py <server_url>
```

Example:
```bash
python paddingattack.py http://localhost:5000
```

## How it Works

1. The script retrieves an authentication token from the target server
2. It performs the padding oracle attack to decrypt the token
3. Extracts the secret message from the decrypted content
4. Creates a new encrypted message by appending " plain CBC is not secure!" to the secret
5. Sends the forged encrypted message back to the server

## Features

- Automatic token retrieval and parsing
- Block-by-block decryption using padding oracle
- Custom message encryption using CBC mode
- Progress visualization during decryption
- Colored output for better readability

## Implementation Details

- Block size: 16 bytes (128 bits)
- Padding scheme: PKCS#7
- Uses XOR operations for CBC mode implementation
- Handles both encryption and decryption operations

## Security Note

This implementation is for educational purposes only. It demonstrates the insecurity of CBC mode when implemented with a padding oracle vulnerability. Do not use this against systems without explicit permission.

👨‍💻 Author:
Md. Mehedi Faruk

📧 mehedifaruk@gmail.com

## License

This project is intended for educational purposes only. Use responsibly and only on systems you have permission to test.
