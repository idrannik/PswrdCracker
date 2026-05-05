Here are the inputs:
Unsalted dictionary (-nh ↔ -d)
python cracker.py -hf -nh -i passwords.txt -w -o hashes.txt
python cracker.py -cf -d -i hashes.txt -w -o recovered.txt
python cracker.py -hf -nh -i recovered.txt -w -o roundtrip.txt
diff hashes.txt roundtrip.txt

Salted dictionary (-sh ↔ -sd)
python cracker.py -hf -sh -i passwords.txt -salt pepper -w -o salted.txt
python cracker.py -cf -sd -i salted.txt -w -o recovered.txt
python cracker.py -hf -sh -i recovered.txt -salt pepper -w -o roundtrip.txt
diff salted.txt roundtrip.txt

Iterated + salted dictionary (-ih ↔ -id) (it must match on both sides)
python cracker.py -hf -ih -i passwords.txt -salt pepper -it 10000 -w -o iterated.txt
python cracker.py -cf -id -i iterated.txt -it 10000 -w -o recovered.txt
python cracker.py -hf -ih -i recovered.txt -salt pepper -it 10000 -w -o roundtrip.txt
diff iterated.txt roundtrip.txt

Brute force (-nh ↔ -b) — only recovers passwords in a-z0-9, length ≤5
python cracker.py -hf -nh -i passwords.txt -w -o hashes.txt
python cracker.py -cf -b -i hashes.txt -w -o recovered.txt # uncracked entries dropped
python cracker.py -hf -nh -i recovered.txt -w -o roundtrip.txt # subset of hashes.txt