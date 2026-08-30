all:	rsa_assign_1	dh_assign_1

clean:	rsa_clean dh_clean

rsa_assign_1:	rsa_assign_1.c
	gcc -o rsa_assign_1 rsa_assign_1.c -lgmp
	
dh_assign_1:	dh_assign_1.c
	gcc -o dh_assign_1 dh_assign_1.c 
	
rsa_clean:	rsa_assign_1.c
	rm rsa_assign_1
	
dh_clean:	dh_assign_1.c
	rm dh_assign_1
