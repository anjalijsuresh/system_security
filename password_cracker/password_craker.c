/*******************************************************************************
*PASSWORD_CRACKING_PROGRAM                                                    * 
*******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

time_t start_time, end_time;
int user_count=0, password_count = 0;

/*******************structure for password ************************************/
struct password
{
	char encrypted[50];
	char password[50];
}possible_pass[25000];

/*******************structure for user details*********************************/
struct user_details
{
	char name[10];
	char encrypted[30];
}user[80000];

struct password *struct_passwd = NULL;
struct user_details *user_struct = NULL;

/*****************function perfoms like "unshadow command"********************/
void unshadow(char pass[], char shado[])
{
	char line[256], shado_line[256], name[200];
	char *encrypt, *string;
	FILE *pass_ptr = NULL, *shado_ptr = NULL, *password_ptr = NULL;
	pass_ptr = fopen(pass, "r");
	shado_ptr = fopen(shado, "r");
	password_ptr = fopen("passwordfile.txt", "w");
	while(1)
	{
		if(fgets(line, 200, pass_ptr) == NULL)
			break;
		line[strlen(line)] = 0;
		strcpy(name, line);
		strtok(name, ":");
		fgets(shado_line, 200, shado_ptr);
		encrypt = strstr(shado_line, "$");
		strtok(encrypt, ":");
		string  =strstr(line, ":");
		string = string + 2;
		fprintf(password_ptr, "%s:%s%s", name, encrypt, string);
	}
	fclose(pass_ptr);
	fclose(shado_ptr);
	fclose(password_ptr);
}

/******************function for extracting password and salt*********************/
char *extract_pass()
{
	FILE *password_ptr = NULL;
	char *password, *name;
	int delim = '$', count = 0;
	char username[10], line[1000], salt[10], encrypt[50];
	password_ptr = fopen("passwordfile.txt", "r");
	user_struct = user;
	while(1)
	{
		if(fgets(line, 120, password_ptr) == NULL)
			break;
		password = strstr(line, "$");
		password = strtok(password, ":");
		strcpy(encrypt, password);
		strcpy(user_struct->encrypted, encrypt);
		name = strrchr(password, delim);
		name++;
		memcpy(salt, password, name-password-1);
		salt[name-password-1] = 0;        
		password = strtok(line, ":");
		strcpy(username, password);
		strcpy(user_struct->name, username);
		user_struct++;
		user_count++;
	}
	strcpy(password, salt);
	return (char *)password;
}

/************function for convert the possible password into encrypted***********/
void poss_password_hash(char dictfile[], char *salt)
{
	FILE *dict_file_ptr;
	char line[100], poss_pass[100], *password;
	int delim1 = '\t', count=0;
	dict_file_ptr = fopen(dictfile, "r");
	struct_passwd = possible_pass;
	while(1)
	{
		if(fgets(line, 100, dict_file_ptr) == NULL)
			break;
		password = strtok(line, "\n");
		password = strrchr(password, delim1);
		++password;
		strcpy(poss_pass, password);
		strcpy(struct_passwd->encrypted, crypt(poss_pass, salt));
		strcpy(struct_passwd->password, poss_pass);
		struct_passwd++;
		password_count++;
	}
}


void main(int argc, char const *argv[])
{
	start_time = clock();
	FILE *output_ptr;
	extern char *optarg;
	char passfile[50], shadofile[50], dictfile[50], outfile[50], *salt_ptr, salt[10];
	int option, i = 0, j = 0, cracked_count = 0;
	struct password *struct_passwd = NULL;
	struct user_details *user_struct = NULL;

	while((option = getopt(argc, argv, "p:s:d:o:")) != -1)
   	{
   		switch(option)
   		{
   			case 'p':
   			    strcpy(passfile, optarg);
   			    break;
   			case 's':
   			    strcpy(shadofile, optarg);
   			    break;
   			case 'd':
   			    strcpy(dictfile, optarg);
   			    break;
   			case 'o':
   			    strcpy(outfile, optarg);
   			    break;
   			case ':':
   			    printf("Missing option arguments\n");
   			    exit(0);
   			    break;
   			case '?':
   			default:
   			    printf("Invalid option");
   			    exit(0);
   			    break;    
   		}
   	}

   	unshadow(passfile, shadofile);
   	salt_ptr = extract_pass();
   	strcpy(salt, salt_ptr);
   	poss_password_hash(dictfile, salt);
   	user_struct = user;
   	struct_passwd = possible_pass;
   	output_ptr = fopen(outfile, "w");
   	fprintf(output_ptr, "|");
   	for (int i = 0; i < 19; i++)
   	{
   		fprintf(output_ptr, "==");
   	}
   	fprintf(output_ptr, "|\n%-4s %-5s %4s %12s %8s\n|", "|", "Username", ":", "Password", "|");
   	for (int i = 0; i < 19; i++)
   	{
   		fprintf(output_ptr, "==");
   	}
   	fprintf(output_ptr, "|");   	

   	while(i < user_count)
   	{
   		struct_passwd = possible_pass;
   		j = 0;
   		while(j < password_count)
   		{
   			if(strcmp(struct_passwd->encrypted, user_struct->encrypted) == 0)
   			{
   				fprintf(output_ptr, "\n%-5s %-10s %-4s %-16s %s", "|", user_struct->name, ":", struct_passwd->password, "|");
   				cracked_count++;
   			}
   			struct_passwd++;
   			j++;
   		}
   		i=i+1;
   		user_struct++;
   	}

   	fprintf(output_ptr, "\n|");
   	for (int i = 0; i < 19; i++)
   	{
   		fprintf(output_ptr, "==");
   	}
   	fprintf(output_ptr, "|");
   	end_time = clock();
   	printf("Execution time : %f\n", difftime(end_time, start_time) / CLOCKS_PER_SEC);
   	printf("Number of password cracked : %d\n", cracked_count);

   	/*********for printing the execution_time and count of cracked password in file****************/
   	fprintf(output_ptr, "\n| Execution time : %f %12s\n|", difftime(end_time, start_time) / CLOCKS_PER_SEC, "|");
   	for (int i = 0; i < 19; i++)
   	{
   		fprintf(output_ptr, "==");
   	}
   	fprintf(output_ptr, "|\n| Number of password cracked : %d %5s\n|", cracked_count, "|");
   	for (int i = 0; i < 19; i++)
   	{
   		fprintf(output_ptr, "==");
   	}
   	fprintf(output_ptr, "|");
   	/********************************************************************************************/
}
