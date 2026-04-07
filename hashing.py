import hashlib
import argparse
#import "rockyousmall.txt"

wordlist = "rockyousmall.txt"

#################
# Hashing the functions:
##################
def sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def dictionary_attack(hash_to_crack, wordlist, start=0):
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            if i < start:
                continue
            word = word.strip()
            if sha256_hash(word) == hash_to_crack:
                return word
    return None

def get_word_by_line(wordlist, line_number):
    with open(wordlist, "r") as f:
        for i, word in enumerate(f, start=1):
            if i == line_number:
                return word.strip()
    return None

#######################
# Salting hash
########################
salt = "mysalt123"
def salted_hash(password, salt):
    salted = salt + password
    print(f"Salting: '{salt}' + '{password}' = '{salted}'")
    return hashlib.sha256(salted.encode()).hexdigest()

def dictionary_attack_salted(hash_to_crack, salt, wordlist, start=0):
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            if i < start:
                continue
            word = word.strip()
            salted = salt + word
            # print(f"Trying line {i + 1}: {salted}")
            if hashlib.sha256(salted.encode()).hexdigest() == hash_to_crack:
                return word
    return None

####################
# Iterating hashing
#####################
def iterated_hash(password, iterations):
    result = password
    for _ in range(iterations):
        result = hashlib.sha256(result.encode()).hexdigest()
    return result

#############################
# Printing Results
#############################
parser = argparse.ArgumentParser()
parser.add_argument("--start", type=int, default=0,
                    help="Skip this many passwords before starting the attack")
parser.add_argument("--line", type=int, default=None,
                    help="1-based line number from the wordlist to choose and hash")
parser.add_argument("--salt", type=str, default="mysalt123",
                    help="Salt value to use when hashing the chosen password")
args = parser.parse_args()

if args.line is not None:
    selected_password = get_word_by_line(wordlist, args.line)
    if selected_password is None:
        raise SystemExit(f"Line {args.line} does not exist in {wordlist}")

    hash_target = salted_hash(selected_password, args.salt)
   # print(f"Selected line: {args.line}")
   # print(f"Password: {selected_password}")
   # print(f"Salt: {args.salt}")



    result = dictionary_attack_salted(hash_target, args.salt, wordlist, start=args.start)
    if result:
        print(f"Found password: {result}")
        print(f"Found hash: {hash_target}")
        print(f"Found salt: {args.salt}")
    else:
        print("Password not found")
