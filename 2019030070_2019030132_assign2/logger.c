#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

void make_log_file(int file_no, int access_type, int action_denied, const char *file_name){
	char file_line[512];
	uid_t uid = getuid();
	time_t t; 
	struct tm *time_info;
	time(&t);
	time_info = localtime(&t);

	MD5_CTX mdContext;
	int bytes = 0;
    unsigned char file_data[256];
	unsigned char c[MD5_DIGEST_LENGTH];
	char *file_hash = malloc(MD5_DIGEST_LENGTH * sizeof(char) * 2);

	if(file_no == -1)
		file_hash = "NULL";
	else {
		MD5_Init(&mdContext);
		bytes = read(file_no, file_data, 256);

		if (bytes > 0){
			while(bytes > 0){
				MD5_Update(&mdContext, file_data, bytes);
				bytes = read(file_no, file_data, 256);
			}  
			MD5_Final (c, &mdContext);
		}
		else if(bytes == 0){
			MD5_Update(&mdContext, file_data, bytes);
			MD5_Final(c, &mdContext);           
		}
		
		int length = 0;
		for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
			int sprintf_full_path = sprintf(file_hash + length, "%02x", c[i]);
			if (sprintf_full_path>0)
				length += sprintf_full_path;
			else
				length = 0;
		}
		}

	int fd = open("file_logging.log", O_WRONLY | O_APPEND | O_CREAT, 0644);

	sprintf(file_line,"%d %s %d-%d-%d %d:%d:%d %d %d %s\n", uid, file_name, time_info->tm_mday, time_info->tm_mon, time_info->tm_year+1900, 
	time_info->tm_hour, time_info->tm_min, time_info->tm_sec, access_type, action_denied, file_hash);

	write(fd, file_line, strlen(file_line));

	close(fd);
}

FILE *fopen(const char *path, const char *mode) {
	printf("In our own fopen, opening %s.\n", path);
	int action_denied, access_type, fd;
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	struct stat buffer;

	if (stat (path, &buffer) == 0)
		access_type = 1;
	else 
		access_type = 0;

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	if (original_fopen_ret) {
		action_denied = 0;
		fd = fileno(original_fopen_ret);
	} else { 
		action_denied = 1;
		fd = -1;
	}

	if(fd != -1){
		char full_path[1024];
		char temp_path[1024];
		sprintf(temp_path, "/proc/self/fd/%d", fileno(original_fopen_ret));
		memset(full_path, 0, sizeof(full_path));
		readlink(temp_path, full_path, sizeof(full_path)-1);
		path = full_path;
	}

	if(strcmp(path, "file_logging.log") == 0)
		return original_fopen_ret;
		
	make_log_file(fd, access_type, action_denied, path);

	return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	printf("In our own fwrite, writing to the file.\n");
	int action_denied, access_type;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	if (original_fwrite_ret < size)
		action_denied = 1;
	else
		action_denied = 0;

	access_type = 2;

	char temp_path[1024];
	char full_path[1024];
	sprintf(temp_path, "/proc/self/fd/%d", fileno(stream));
	memset(full_path, 0, sizeof(full_path));
	readlink(temp_path, full_path, sizeof(full_path)-1);
	
	make_log_file(fileno(stream), access_type, action_denied, full_path);

	return original_fwrite_ret;
}
