#include <stdio.h>
#include <string.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	printf("Calling the fopen() function for a file with no access by the user.\n");

	for(int i=0; i<8; i++){
		file = fopen("/home/elena/Lab2/no_access_file.txt", "r+");
		if(file == NULL) printf("fopen() returned null.\n");
		else printf("fopen succeded.\n");
	}

	printf("Calling the fopen() function for 10 files and write to them.\n");
	
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen() returned null.\n");
		else {
			bytes = fwrite(filenames[i], 1, strlen(filenames[i]), file);
			fclose(file);
		}
	}
	
	printf("Calling the fopen() function for 10 files and append to them.\n");

	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "a+");
		if (file == NULL) 
			printf("fopen() returned null.\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

}
