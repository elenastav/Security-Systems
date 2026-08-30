#include <gmp.h>

#include <stdio.h>

#include <assert.h>

#include <stdlib.h>

#include <string.h>

#include <stdbool.h>

#include <unistd.h>

#include <time.h>

void key_Generation(int length, char *public_fname, char *private_fname);

void encrypt(char *input, char *output, char *keys);

void decrypt(char *input, char *output, char *keys);

int main(int argc, char *argv[])
{

    char *input_File, *output_File, *key_File;

    char operation;

    int opt, length;

    // while loop to handle the terminal options

    while ((opt = getopt(argc, argv, ":hi:o:k:g:dea")) != -1)
    {

        switch (opt)

        {

        case 'i':

            input_File = optarg;

            break;

        case 'o':

            output_File = optarg;

            break;

        case 'k':

            key_File = optarg;

            break;

        case 'g':
            operation = 'g';
            length = atoi(optarg);

            break;

        case 'd':

            operation = 'd';

            break;

        case 'e':

            operation = 'e';

            break;

        case 'a':

            operation = 'a';

            break;

        case 'h':

            printf("Options:\n-i path Path to the input file\n-o path Path to the output file\n-k path Path to the key file\n-g Perform RSA key-pair generation\n-d Decrypt input and store results to output\n");
            printf("-e Encrypt input and store results to output\n-h This help message\n");
            printf("\nThe arguments “i”, “o” and “k” are always required when using “e” or “d”\nUsing -i and a path the user specifies the path to the input file.\n");
            printf("Using -o and a path the user specifies the path to the output file.\nUsing -k and a path the user specifies the path to the key file.\n");
            printf("Using -g the tool generates a public and a private key given a key length “length” and stores them to the public_length.key and private_length.key files respectively.\n");
            printf("Using -d the user specifies that the tool should read the ciphertext from the input file, decrypt it and then store the plaintext in the output file.\n");
            printf("Using -e the user specifies that the tool should read the plaintext from the input file, encrypt it and store the ciphertext in the output file.");
            printf("Using -a the user generates three distinct sets of public and private key pairs, allowing for a comparison of the encryption and decryption times for each.");

            return 0;

        case '?':

            printf("Error");

            return 1;

        case ':':

            printf("Not enough arguments.");

            return 0;

        default:

            printf("Missing arguments.\n");

            return 0;
        }
    }

    // Key generation

    if (operation == 'g')

        key_Generation(length, "public_length.key", "private_length.key");

    // Encryption case

    else if (operation == 'e')
    {
        encrypt(input_File, output_File, key_File);
    }

    // Decryption

    else if (operation == 'd')
    {
        decrypt(input_File, output_File, key_File);
    }

    else if (operation == 'a')
    {
        int key_lengths[] = {16, 32, 64};
        char *fnames[] = {"public_16.key",
                          "public_32.key",
                          "public_64.key",
                          "private_16.key",
                          "private_32.key",
                          "private_64.key"};

        // Open performance.txt in append mode
        FILE *file = fopen("performance.txt", "a");
        clock_t start;
        clock_t end;

        // Loop through different key lengths for comparison
        for (int i = 0; i < 3; i++)
        {

            key_Generation(key_lengths[i], fnames[i], fnames[i + 3]);

            // Measure encryption time
            start = clock();
            encrypt("plaintext.txt", "encrypted.txt", fnames[i]);
            end = clock();
            double encryption_time = ((double)(end - start)) / CLOCKS_PER_SEC;

            // Measure decryption time
            start = clock();
            decrypt("encrypted.txt", "decrypted.txt", fnames[i + 3]);
            end = clock();
            double decryption_time = ((double)(end - start)) / CLOCKS_PER_SEC;

            // Write measurements to performance.txt
            fprintf(file, "Key Length: %d bits\n", key_lengths[i]);
            fprintf(file, "Encryption Time: %f seconds\n", encryption_time);
            fprintf(file, "Decryption Time: %f seconds\n\n", decryption_time);
        }
        // Close the file
        fclose(file);
    }

    return 0;
}

// Function to generate RSA key pair based on the specified key length
void key_Generation(int length, char *public_fname, char *private_fname)
{
    mpz_t p, q, n, lambdan, e, d, rop, r;

    // Seed the random number generator
    srand(time(NULL));

    mpz_init(p);
    mpz_set_ui(p, 0);

    mpz_init(q);
    mpz_set_ui(q, 0);

    gmp_randstate_t state;
    gmp_randinit_default(state);

    // Generate random numbers of the specified length

    mpz_urandomb(p, state, length / 2);
    mpz_urandomb(q, state, length / 2);

    // Make sure the most significant bit is set to 1

    mpz_setbit(p, length / 2 - 1);
    mpz_setbit(q, length / 2 - 1);

    do
    {
        // Find the next prime after the generated random numbers
        mpz_nextprime(p, p);
        mpz_nextprime(q, q);

    } while (!(mpz_probab_prime_p(p, 50) && mpz_probab_prime_p(q, 50)));

    // Clears the GMP random state to release resources used for random number generation.
    gmp_randclear(state);

    // Initializes a new GMP integer n to store the modulus (n = p * q) for RSA encryption and decryption.
    // p and q are prime numbers used to calculate n.
    mpz_init(n);
    mpz_set_ui(n, 0);
    mpz_mul(n, p, q);

    // Computes p - 1 and q - 1 and stores the results in p and q.
    // Then, initializes lambdan as (p - 1)(q - 1), which is used in RSA's Euler's totient function.
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_init(lambdan);
    mpz_set_ui(lambdan, 0);
    mpz_mul(lambdan, p, q);

    // Initializes GMP integers e, rop, and r.
    // e represents the public exponent.
    // rop and r are temporary variables used in the generation of e.
    mpz_init(e);
    mpz_set_ui(e, 1);
    mpz_init(rop);
    mpz_init(r);

    // Generates a random integer e and checks if it satisfies conditions for being a suitable public exponent.
    // The loop continues until a valid e is found: it should be prime, greater than 1, less than lambdan, and coprime with lambdan.

    do
    {
        srand(time(0));
        mpz_set_ui(e, rand() % 1000);
        mpz_gcd(rop, e, lambdan);
        mpz_mod(r, e, lambdan);
    }

    while (!(mpz_probab_prime_p(e, 30) == 2 && mpz_cmp_ui(r, 0) != 0 && mpz_cmp_ui(rop, 1) == 0));

    // Initializes d and calculates its modular inverse with respect to e modulo lambdan.
    // d represents the private exponent used in RSA decryption.
    mpz_init(d);
    mpz_invert(d, e, lambdan);

    FILE *fp1, *fp2;
    fp1 = fopen(public_fname, "w");
    mpz_out_str(fp1, 10, n);
    fprintf(fp1, " ");
    mpz_out_str(fp1, 10, d);
    fclose(fp1);

    fp2 = fopen(private_fname, "w");
    mpz_out_str(fp2, 10, n);
    fprintf(fp2, " ");
    mpz_out_str(fp2, 10, e);
    fclose(fp2);
}

// Function to perform encryption
void encrypt(char *input_File, char *output_File, char *key_File)
{
    // Open input, output, and key files in read or write mode as necessary
    FILE *input, *output, *keys;
    input = fopen(input_File, "r");
    output = fopen(output_File, "w+");
    keys = fopen(key_File, "r");

    // Declare variables to store public key components (n and e), encrypted text, and temporary values
    mpz_t n, e, encrypted, starting;
    int flag;
    int key_size = 0;

    // Determine the size of the key file to allocate memory for reading key components
    fseek(keys, 0L, SEEK_END);
    key_size = ftell(keys);
    rewind(keys);

    // Declare arrays to store key components read from the file
    char nString[key_size / 2], eString[key_size / 2];

    // Read n and e values from the key file and initialize corresponding GMP integers
    fscanf(keys, "%s %s", nString, eString);
    mpz_init(n);
    flag = mpz_set_str(n, nString, 10);
    assert(flag == 0);
    mpz_init(e);
    flag = mpz_set_str(e, eString, 10);
    assert(flag == 0);

    int size = 0;
    // Determine the size of the input file to allocate memory for reading characters
    fseek(input, 0L, SEEK_END);
    size = ftell(input);
    rewind(input);

    char cur_char = 0;

    // Initialize GMP integers for encryption process and arrays to store encrypted values
    mpz_init(encrypted);
    mpz_init(starting);

    long long int encrypted_Array[size];
    long long int tmp[size];

    size = 0;
    // Read characters from the input file, encrypt them, and store the encrypted values in an array
    while ((cur_char = fgetc(input)) != EOF)
    {
        long long int tmp;
        int ascii_Tmp = cur_char;

        mpz_set_ui(starting, ascii_Tmp);
        mpz_powm(encrypted, starting, e, n);
        tmp = mpz_get_ui(encrypted);

        encrypted_Array[size] = tmp;

        size++;
    }

    // Write the encrypted array to the output file
    fwrite(encrypted_Array, sizeof(long long int), size, output);

    // Close input, output, and key files after processing
    fclose(input);
    fclose(output);
    fclose(keys);
}

// Function to perform decryption
void decrypt(char *input_File, char *output_File, char *key_File)
{
    // Open input, output, and key files in read or write mode as necessary
    FILE *input, *output, *keys;
    input = fopen(input_File, "rb");
    output = fopen(output_File, "w");
    keys = fopen(key_File, "r");

    // Declare variables to store private key components (n and d), decrypted text, and starting value for decryption
    mpz_t n, d, decrypted, starting;

    int flag;
    int key_size = 0;
    // Determine the size of the key file to allocate memory for reading key components
    fseek(keys, 0L, SEEK_END);
    key_size = ftell(keys);
    rewind(keys);

    // Declare arrays to store key components read from the file
    char nString[key_size / 2], dString[key_size / 2];

    // Read n and d values from the key file and initialize corresponding GMP integers
    fscanf(keys, "%s %s", nString, dString);
    mpz_init(n);
    flag = mpz_set_str(n, nString, 10);
    assert(flag == 0);
    mpz_init(d);
    flag = mpz_set_str(d, dString, 10);
    assert(flag == 0);

    int file_Size = 0;
    // Determine the size of the input file to calculate the number of characters in the decrypted text
    fseek(input, 0L, SEEK_END);
    file_Size = ftell(input);
    rewind(input);

    char cur_char = 0;

    // Calculate the number of characters in the decrypted text (subtract 8 bytes for null terminator and divide by 8)

    file_Size = (file_Size - 8) / 8;

    mpz_init(decrypted);
    mpz_init(starting);

    long long int decrypted_Array[file_Size];
    int ascii;

    fread(&decrypted_Array, sizeof(long long int), file_Size, input);

    char result[file_Size + 1];

    // Decrypt each value in the array and convert it back to ASCII representation
    for (int i = 0; i < file_Size; i++)
    {
        mpz_set_ui(starting, decrypted_Array[i]);
        mpz_powm(decrypted, starting, d, n);

        ascii = mpz_get_ui(decrypted);

        result[i] = ascii;
    }

    // Add null terminator to the result string
    result[file_Size] = '\0';

    fwrite(result, sizeof(char), file_Size, output);
    fclose(input);
    fclose(output);
    fclose(keys);
}

