# Encrypted File Vault (AES)

Encrypt and decrypt files using AES with password-derived keys (PBKDF2).

## Usage

```bash
pip install -r requirements.txt
python vault.py encrypt file.txt -p mypassword
python vault.py decrypt file.txt.enc -p mypassword
```
