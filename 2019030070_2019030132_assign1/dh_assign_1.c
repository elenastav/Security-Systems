#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	printf("\n");

	int p, g, a, b, s, opt;
	char *output = NULL;

	// Parse command-line options using getopt
	while ((opt = getopt(argc, argv, ":ho:p:g:a:b:")) != -1)
	{
		switch (opt)
		{
		case 'o':
			output = optarg;
			break;
		case 'p':
			p = atoi(optarg);
			break;
		case 'g':
			g = atoi(optarg);
			break;
		case 'a':
			a = atoi(optarg);
			break;
		case 'b':
			b = atoi(optarg);
			break;
		case 'h':
			printf("Options:\n-o path Path to output file\n-p number Prime number\n-g number Primitive Root for previous prime number\n-a number Private key A\n-b number Private key B\n-h	This help message\n");
			printf("The argument -p will include the will be the public prime number.\nThe argument -g will be the public primitive root of the previous prime number.\nThe argument -a will be the private key of user A.\n");
			printf("The argument -b will be the private key of user B.\n");
			return 1;
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

	// Calculate A, B and the shared secret s
	int A = (g ^ a) % p;
	int B = (g ^ b) % p;
	int sA = (B ^ a) % p;
	int sB = (A ^ b) % p;

	FILE *fp;
	fp = fopen(output, "w+");

	// Check if the calculated shared secrets match
	if (sA != sB)
	{
		printf("Error\n");
		return -1;
	}
	else
	{
		s = sA;
	}
	// Write A, B and the shared secret s to the output file
	fprintf(fp, "%d, %d, %d\n", A, B, s);
	fclose(fp);
	return 0;
}
