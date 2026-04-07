import itertools
import string

def brute_force(hash_to_crack, max_length=4):
    chars = string.ascii_lowercase + string.digits

    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            guess = ''.join(guess)
            if sha256_hash(guess) == hash_to_crack:
                return guess
    return None