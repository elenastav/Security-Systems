MAKEFILE:
To compile all programs using the Makefile: make all
To create/update file_logging.log: make run 
To remove the generated files: make clean

Access Control Logging tool:
A shared library named "logger.so" was created to override fwrite() and fopen(). These functions needed
to be modified in a way that file creation, file opening and file modification were logged. 

Access Control Log Monitoring tool:
The first function that was requested prints the uids of all malicious users. The second prints a text describing what uids modified a specific file and how many times each. Using file_logging.log, a linked list of structs was created in order to finally implement the functions.

Test the Access Control Logging & Log Monitoring tools:
To test both tools, first with the chmod 000 no_access_file.txt command all rights are removed from a file. So, after trying to access that file, an error message is printed. Then, 10 files are created with fopen(), 10 logs with access_type 2 are also created with fwrite(). Finally, opening these files again creates 10 logs with access_type 1 and appending text to them creates 10 logs with access_type 2.