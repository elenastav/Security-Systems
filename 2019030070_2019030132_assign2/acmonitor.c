#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct entry 
{
	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
    struct entry *next; /*pointer for linked list*/

};

struct user_list
{
	int uid;
	int count;
	struct user_list *next;
};

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

struct entry *read_file_logging(FILE *fp)
{
	struct entry *head = NULL;
	struct entry *current = head;
	struct entry *node = (struct entry *)malloc(sizeof(struct entry));
	char * line = NULL;
    size_t len = 0;
    ssize_t read;

	if (fp == NULL)
        exit(EXIT_FAILURE);

	while((read = getline(&line, &len, fp)) != -1){
		char *str[7];

		char *st = strtok(line, " ");
		
		int counter = 0;

		while(st != NULL){
			str[counter] = st;
			st = strtok(NULL, " ");
			counter++;
		}

       node->uid = atoi(str[0]);
 
       node->file = (char *)malloc((strlen(str[1]) + 1) * sizeof(char));
       strcpy(node->file, str[1]);

       node->date = (time_t)malloc((strlen(str[2]) + 1) * sizeof(char));
       strcpy(ctime(&(node->date)), str[2]);

        node->time = (time_t)malloc((strlen(str[3]) + 1) * sizeof(char));
        strcpy(ctime(&(node->time)), str[3]);

        node->access_type = atoi(str[4]);
        node->action_denied = atoi(str[5]);

        node->fingerprint = (char *)malloc((strlen(str[6]) + 1) * sizeof(char));
        strcpy(node->fingerprint, str[6]);

        node->next = NULL;

        if (head == NULL) {
            head = node;
        } else {
			
        while (current->next != NULL) {
        current = current->next;
        }
        current->next = node;
        }
	}

	if(line) free(line);

	return head;
}

void list_unauthorized_accesses(FILE *log)
{  
    int max_count = 7;
    struct entry *head = read_file_logging(log);
    struct entry *current = head;
	struct user_list *user = NULL;

	while(current != NULL){
		if(current->action_denied == 1){
			
			if(user == NULL){
				user = (struct user_list *)malloc(sizeof(struct user_list));
				user->uid = current->uid;
				user->count++;
				user->next = NULL;
			}
			else{	
				struct user_list *cur_user = user;

				while((cur_user != NULL) && (cur_user->uid != current->uid))
					cur_user = cur_user->next; 
					
				if(cur_user == NULL){
					cur_user = (struct user_list *)malloc(sizeof(struct user_list));
					cur_user->uid = current->uid;
					cur_user->count++;
					cur_user->next = user;
					user = cur_user;
				}
				else{
					cur_user->count++;
				}
			}
		}
		current = current->next;
	}

	int counter = 0;

	while(user){
		if(user->count >= 7){
			printf("Unauthorized access detected for user with ID: %d\n", user->uid);
			counter++;
		}
		user = user->next;
	}

	if(counter == 0) printf("No unauthorized users detected\n");
}

void list_file_modifications(FILE *log, char *file_to_scan)
{
	struct entry *head = read_file_logging(log);
	struct entry *current = head;
	struct user_list *user = NULL;

	while(current != NULL){
		if((strstr(current->file, file_to_scan) != NULL) && ((current->access_type == 2) )){
			
			if(user == NULL){
				user = (struct user_list *)malloc(sizeof(struct user_list));
				user->uid = current->uid;
				user->count++;
				user->next = NULL;
			}
			else{	
				struct user_list *cur_user = user;

				while((cur_user != NULL) && (cur_user->uid != head->uid))
					cur_user = cur_user->next; 
					
				if(cur_user == NULL){
					cur_user = (struct user_list *)malloc(sizeof(struct user_list));
					cur_user->uid = current->uid;
					cur_user->count++;
					cur_user->next = user;
					user = cur_user;
				}
				else{
					cur_user->count++;
				}
			}
		}
		current = current->next;
	}
	int counter = 0;

	while(user){
		printf("User ID %d has made %s modifications to %d.\n", user->uid, file_to_scan, user->count);
		counter++;
		user = user->next;
	}

	if(counter == 0) printf("This file has not been modified by any user.\n");
}


int main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
