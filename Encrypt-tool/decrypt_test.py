from encrypt import decrypt_file_with_private_key

private_key = """-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----"""

decrypt_file_with_private_key(
    "sandbox/file1.txt.locked",
    private_key,
)
