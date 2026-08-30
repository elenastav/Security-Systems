MAKEFILE:
To compile both programs using the Makefile: make all 
To remove the generated files: make clean

DH CODE:
The dh_assign_1.c performs Diffie-Hellman key exchange based on command-line parameters. It calculates shared secrets A, B, and s, writes them to an output file and checks for errors. The program accepts options like -o, -p, -g, -a, and -b to specify file paths, prime numbers, primitive roots and private keys.

RSA C0DE:
The rsa_assign_1.c performs various operations related to RSA encryption and decryption. More specifically:  
->Key Generation (-g): Generates RSA public and private keys of specific length and saves them in separate files.
->Encryption (-e): Encrypts plaintext from an input file using a provided public key and saves the ciphertext to an output file.
->Decryption (-d): Decrypts ciphertext from an input file using a provided private key and saves the plaintext to an output file.
->Performance Testing (-a): Measures the performance of encryption and decryption for different key lengths and logs results to "performance.txt."

PROBLEMS:
The rsa code has trouble handling large key lengths. So, in option -a, we run performance tests for key lengths of 16, 32, and 64 bits to see how well RSA encryption and decryption work with these key sizes.


