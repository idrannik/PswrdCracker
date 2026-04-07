import hashlib

def salted_hash(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

# Read a password from rockyousmall.txt and hash it with salt
with open("rockyousmall.txt", "r") as f:
    lines = f.readlines()

# Pick the first password as an example
password = lines[0].strip()
salt = "mysalt123"  # You can change this salt
hashed = salted_hash(password, salt)

print(f"Password: {password}")
print(f"Salt: {salt}")
print(f"Salted Hash: {hashed}")
print(f"\nCopy this into cracker.py:")
print(f'hash_target = "{hashed}"')
print(f'salt = "{salt}"')
print(f'result = dictionary_attack_salted(hash_target, salt, "rockyousmall.txt")')
