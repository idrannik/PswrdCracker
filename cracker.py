import hashlib
import argparse
import time
import itertools
import string

wordlist = "rockyousmall.txt"

start_time = time.time()   
def show_time(start_time):
    print("time to run: %s seconds " % (time.time() - start_time))


#############################
# Arguements
#############################
parser = argparse.ArgumentParser()
from pathlib import Path

mode = parser.add_mutually_exclusive_group(required = True)
mode.add_argument("-cf", action="store_true", help="Cracking mode")
mode.add_argument("-hf", action="store_true", help="Hashing mode")


parser.add_argument("-t", action="store_true", default=0, help="Display run time")
parser.add_argument("-w", action="store_true", help="Write output to file")
parser.add_argument("-start", type=int, default=0, help="Skip this many passwords before starting the attack")
parser.add_argument("-i", type=Path, default="hashes.txt", help="Input file name. ex: Hashes.txt")
parser.add_argument("-o", type=Path, default="output.txt", help="Output file name. ex: Hashes.txt")


# Cracking Args
parser.add_argument("-d", action="store_true", help="Dictionary attack")
parser.add_argument("-id", action="store_true", help="Iterated dictionary attack")
parser.add_argument("-sd", action="store_true", help="Salted Dictionary attack")
parser.add_argument("-b", action="store_true", help="Brute force attack")


# Hashing args
parser.add_argument("-nh", action="store_true", help="Normal Hashing")
parser.add_argument("-sh", action="store_true", help="Salted Hashing")
parser.add_argument("-ih", action="store_true", help="Iterated Hashing")
parser.add_argument("-line", type=int, default=None, help="1-based line number from the wordlist to choose and hash")
parser.add_argument("-it", type=int, default=1, help="Number of SHA256 iterations to apply to the salted hash")
parser.add_argument("-salt", type=str, default="mysalt123", help="Salt value to use when hashing the chosen password")

args = parser.parse_args()

salt = args.salt
iterations = args.it

output_file = args.o # Output file of hash or attack inputed through -o argument
input_file = args.i  # Input file of hash or attack inputed through -p argument

def load_hashes(input_file): # loads input file
    file = []
    with open(input_file, "r") as f:
        for line in f:
            file.append(line.strip())
        return file

def get_word_by_line(wordlist, line_number):
    with open(wordlist, "r") as f:
        for i, word in enumerate(f, start=1):
            if i == line_number:
                return word.strip()
    return None


#############################
# Attacks                           #!!! issues: sorts outputs out of order because they are based on the wordlist. also does not mention if a password was not able to be cracked.
#############################
def dictionary_attack(hashes, wordlist, start): # dictionary attack -d
    cracked = {}
    remaining = set(hashes)
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            if not remaining:
                break
            if i < start:
                continue
            word = word.strip()
            hash_word = hashlib.sha256(word.encode()).hexdigest()
            if hash_word in remaining:
                cracked[hash_word] = word
                remaining.discard(hash_word)
    return cracked

def iterated_dictionary_attack(hashes, wordlist, start, iterations): # iterated dictionary attack -id
    cracked = {}
    by_salt = {}            # salt_hex -> { stored_hash: line }
    for line in hashes:
        parts = line.split(":")
        if len(parts) != 2:
            continue
        salt_hex, stored_hash = parts
        by_salt.setdefault(salt_hex, {})[stored_hash] = line
    remaining_by_salt = {s: set(d.keys()) for s, d in by_salt.items()}
    total = sum(len(d) for d in by_salt.values())
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            if len(cracked) == total:
                break
            if i < start:
                continue
            word_bytes = word.strip().encode()
            for salt_hex, remaining in remaining_by_salt.items():
                if not remaining:
                    continue
                salt_bytes = bytes.fromhex(salt_hex)
                h = hashlib.sha256(salt_bytes + word_bytes).hexdigest()
                for _ in range(iterations):
                    h = hashlib.sha256(h.encode()).hexdigest()
                if h in remaining:
                    cracked[by_salt[salt_hex][h]] = word.strip()
                    remaining.discard(h)
    return cracked


def salted_dictionary_attack(hashes, wordlist, start): # salted dictionary attack -sd
    cracked = {}
    entries = []
    for line in hashes:
        parts = line.split(":")
        if len(parts) != 2:
            continue
        entries.append((line, bytes.fromhex(parts[0]), parts[1]))
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            if len(cracked) == len(entries):
                break
            if i < start:
                continue
            word = word.strip()
            for line, salt_bytes, stored_hash in entries:
                if line in cracked:
                    continue
                hashed_guess = hashlib.sha256(salt_bytes + word.encode()).hexdigest()
                if hashed_guess == stored_hash:
                    cracked[line] = word
    return cracked

def brute_force_attack(hashes, max_length=5): # Brute force attack -b
    cracked = {}
    remaining = set(hashes)
    chars = string.ascii_lowercase + string.digits
    for length in range(1, max_length + 1):
        if not remaining:
            break
        for guess in itertools.product(chars, repeat=length):
            guess_str = ''.join(guess)
            hashed_guess = hashlib.sha256(guess_str.encode()).hexdigest()
            if hashed_guess in remaining:
                cracked[hashed_guess] = guess_str
                remaining.discard(hashed_guess)
                if not remaining:
                    break
    return cracked

#############################
# Hashing
#############################
def sha256_hash(input_file):            # normal sha256 hashing -nh 
    hashed = []
    with open(input_file, "r") as f:
        for line in f:
            hashes = hashlib.sha256(line.strip().encode()).hexdigest()
            hashed.append(hashes)
    return hashed

def iterated_hash(input_file, iterations, salt):  # iterated sha 256 hashing -ih (salted + iterated, emits salt_hex:hash)
    salt_bytes = salt.encode()
    salt_hex = salt_bytes.hex()
    hashed = []
    with open(input_file, "r") as f:
        for line in f:
            pw = line.strip()
            result = hashlib.sha256(salt_bytes + pw.encode()).hexdigest()
            for _ in range(iterations):
                result = hashlib.sha256(result.encode()).hexdigest()
            hashed.append(f"{salt_hex}:{result}")
    return hashed


def salted_hash(input_file, salt): # salted sha256 hashing -sh (emits salt_hex:hash)
    salt_bytes = salt.encode()
    salt_hex = salt_bytes.hex()
    hashed = []
    with open(input_file, "r") as f:
        for line in f:
            pw = line.strip()
            h = hashlib.sha256(salt_bytes + pw.encode()).hexdigest()
            hashed.append(f"{salt_hex}:{h}")
    return hashed


#############################
# Printing Results
#############################
if args.cf:
    file = load_hashes(args.i)              # cracking mode, takes results of choosen attack and outputs them to terminal or a file if -w is used as an argument
    result = None

    if args.d:
            result = dictionary_attack(file, wordlist, args.start)
    elif args.id:
            result = iterated_dictionary_attack(file, wordlist, args.start, iterations)
    elif args.sd:
            result = salted_dictionary_attack(file, wordlist, args.start)
    elif args.b:
            result = brute_force_attack(file)

    else:
        print("Choose an attack: -d, -id, -sd, or -b")
        raise SystemExit

    display_lines = []
    cracked_pws = []
    for h in file:
        if h in result:
            display_lines.append(f"{h} -> {result[h]}")
            cracked_pws.append(result[h])
        else:
            display_lines.append(f"{h} -> UNCRACKED")
    display_output = "\n".join(display_lines) if display_lines else "**Attack Failed**"

    if args.w:
        with open(output_file, "w") as f:
            if cracked_pws:
                f.write("\n".join(cracked_pws) + "\n")
        print(f"Passwords saved to {output_file} ({len(cracked_pws)}/{len(file)} cracked)")
    else:
        print(display_output)


elif args.hf:           # Hashing mode, takes results of choosen hash function and outputs them to terminal or a file if -w is used as an argument
    
    if args.nh:
        result = sha256_hash(input_file)
    elif args.ih:
        result = iterated_hash(input_file, iterations, salt)
    elif args.sh:
        result = salted_hash(input_file, salt)
    else:
        print("Choose a hashing mode: -nh, -ih, or -sh")
        raise SystemExit
    if result:
        output="\n".join(result)
    else: 
        output=f"**Hash Failed**"

    if args.w:
        if args.o:
            with open(output_file, "w") as f:
                f.write(output + "\n")
                print(f"Hashes saved to {output_file}")
        else:
            with open("Hashes.txt", "w") as f:
                f.write(output + "\n")
                print("Hashes saved to Hashes.txt")
    else:
        print(output)
 

if args.t:
    show_time(start_time)       # shows runtime if -t arguement is used -t

    
