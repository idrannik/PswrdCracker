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

salt = "mysalt123"
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
def dictionary_attack(file, wordlist, start): # dictionary attack -d
    found = []
    with open(wordlist, "r") as f:
        for i, word in enumerate(f):
            if i < start:
                continue
            word = word.strip()
            hash_word = hashlib.sha256(word.encode()).hexdigest()  
            if hash_word in file:
                found.append(word)
    return found

def iterated_dictionary_attack(file, wordlist, start): # broken iterated dictionary attack -id  
    found = []
    with open (wordlist, "r") as f:
        for i, word in enumerate(f):
            if i < start:
                continue
            word = word.strip()

            for line in file:
                parts = line.split(":")
                if len(parts) !=2:
                    continue
                salt_hex = parts[0]
                stored_hash = parts[1]
                salt = bytes.fromhex(salt_hex)
                hashed = hashlib.sha256(salt + word.encode()).hexdigest()
                for j in range(10000):
                    hashed = hashlib.sha256(hashed.encode()).hexdigest()    
                if hashed == stored_hash:
                    found.append(word)
    return found
    

def salted_dictionary_attack(file, wordlist, start): # broken salted dictionary attack -sd
    found = []
    with open (wordlist,"r") as f:
        for i, word in enumerate(f):
            if i < start:
                continue
            word = word.strip()
            for line in file:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                salt_hex = parts[0]
                stored_hash = parts[1]
                salt = bytes.fromhex(salt_hex)
                hashed_guess = hashlib.sha256(salt + word.encode()).hexdigest()
                if hashed_guess == stored_hash:
                    found.append(word)
    return found

def brute_force_attack(hashes, max_length=4): # Brute force attack -b
    found = []
    chars = string.ascii_lowercase + string.digits
    for hash in file:
        for length in range(1, 5):
            for guess in itertools.product(chars, repeat=length):
                guess_str = ''.join(guess)
                hashed_guess = hashlib.sha256(guess_str.encode()).hexdigest()
                if hashed_guess == hash:
                    found.append(guess_str)
    return found

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

def iterated_hash(input_file, iterations):  # iterated sha 256 hashing -ih
    hashed = []
    with open(input_file, "r") as f:
        for line in f:
            result = line.strip()
            for _ in range(iterations):                                 #!!! issue: repeats each iteration instead of displaying final value
                result = hashlib.sha256(result.encode()).hexdigest() 
            hashed.append(result)
    return hashed


def salted_hash(input_file, salt): # salted sha256 hashing -sh
    hashed = []
    with open(input_file, "r") as f:
        for line in f:
            salted = salt + line.strip()
            hashes = hashlib.sha256(salted.encode()).hexdigest()
            hashed.append(hashes)
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
            result = iterated_dictionary_attack(file, wordlist, args.start)
    elif args.sd:
            result = salted_dictionary_attack(file, wordlist, args.start)
    elif args.b:
            result = brute_force_attack(file)

    else:
        print("Choose an attack: -d, -id, -sd, or -b")
        raise SystemExit
    if result:
        output= "\n".join(result)
    else: 
        output=f"**Attack Failed**"

    if args.w:
        if args.o:
            with open(output_file, "w") as f:
                f.write(output + "\n")
                print(f"Passwords saved to {output_file}")
        else:
            with open("passwords.txt", "w") as f:
                f.write(output + "\n")
                print("Passwords saved to passwords.txt")
    else:
        print(output)


elif args.hf:           # Hashing mode, takes results of choosen hash function and outputs them to terminal or a file if -w is used as an argument
    
    if args.nh:
        result = sha256_hash(input_file)
    elif args.ih:
        result = iterated_hash(input_file, iterations)
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

    
