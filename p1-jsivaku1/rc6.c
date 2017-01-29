#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Macros for constants defined by RC6 algorithm

#define W 32		//Word size specified
#define lgw 5      	//lg 32=5
#define R 20		//Number of Words
#define keylength 256	//32 bit key size
#define pw 0xB7E15163 	
#define qw 0x9E3779B9



#define ENCRYPTION Encryption
#define DECRYPTION Decryption


//Global variables for RC6 algorithm

FILE *fptr_input, *fptr_output;
char type_of_op[80];
char temp_var[80];
int type_flag;
int b, c;
unsigned int unsigned_var=0;
unsigned int L[keylength / 4];
unsigned int S[2 * R + 4];
unsigned int t, u;
int i;
unsigned int Sa, Sb, Si, Sj;
int Sv;
unsigned int A, B, C, D;




//Rotation function for left shift

unsigned int rotl(unsigned int value, unsigned int shift){

	return ((value << shift) | (value >> (sizeof(unsigned int) * 8 - shift)));

}


//Rotate function for right shift

unsigned int rotr(unsigned int value, unsigned int shift){

	return ((value >> shift) | (value << (sizeof(unsigned int) * 8 - shift)));

}


//Key scheduling algorithm for saving the userkey into the array L[]

int KeySchedule()
{
	//Get the user key and store it in L[c].

		fscanf(fptr_input, "%s", temp_var);

/*		if (strcmp(temp_var,"userkey") != 0){

			printf("1. Invalid file formatting, Make sure to give correct keywords\n");

			fclose(fptr_input);

			exit(-1);

		}
*/
		b = 0;

		c = 0;

		i=0;
		while(i<(keylength/4)){
		L[i]=0;
		i++;
		}

		while (fscanf(fptr_input, "%x", &unsigned_var) == 1){

			c = b / (W / 8);

			L[c] = L[c] | (unsigned_var << ((b % (W / 8)) * 8));

			b++;

		}

		fclose(fptr_input);

		c++;
}


//Encryption function for calling the RC6 encryption implementation

int Encryption(int argc, char** argv)
{

	//Obtaining the value of A,B,C,D

		A = 0x0;

		B = 0x0;

		C = 0x0;

		D = 0x0;

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			A = A | (unsigned_var << (i * 8));
		i++;
		}

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			B = B | (unsigned_var << (i * 8));
		i++;
		}

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			C = C | (unsigned_var << (i * 8));
		i++;
		}

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			D = D | (unsigned_var << (i * 8));
		i++;
		}




//Calling Key Scheduling algorithm

	KeySchedule();




//Compute the array for saving the values S[0,1,2,3,4 ...2r + 3]

		i=0;
		while(i<(2*R+4)){
			S[i]=0;
			i++;
		}

		S[0] = pw;

		i=1;
		while(i < (2 * R + 4)){

			S[i] = S[i - 1] + qw;
		i++;
		}

		Sa = 0;

		Sb = 0;

		Si = 0;

		Sj = 0;

		if(c>2*R+4){
			Sv = 3 * c;
		}
		else{
			Sv = 3 * (2*R+4);
		}

		i=1;
		while(i <= Sv){

			Sa = S[Si] = rotl((S[Si] + Sa + Sb), 3);

			Sb = L[Sj] = rotl((L[Sj] + Sa + Sb), (Sa + Sb));

			Si = (Si + 1) % (2 * R + 4);

			Sj = (Sj + 1) % c;
			i++;
		}



//RC6 implementation function for encryption operation
	RC6EncBlock(argc,argv);
	

}



//Function with RC6 encryption implementation which is being called in Encryption()
int RC6EncBlock(int argc, char** argv)
{
		B = B + S[0];

		D = D + S[1];

		i=1;

		while(i <= R){

			t = rotl((B * (2 * B + 1)), lgw);

			u = rotl((D * (2 * D + 1)), lgw);

			A = rotl(A ^ t, (u & 0x1f)) + S[2 * i];

			C = rotl(C ^ u, (t & 0x1f)) + S[2 * i + 1];

			unsigned_var = A;

			A = B;

			B = C;

			C = D;

			D = unsigned_var;
			i++;
		}

		A = A + S[2 * R + 2];

		C = C + S[2 * R + 3];

		fptr_output = fopen(argv[argc - 1], "w");

//Checking if output file can be opened for writing the result

		if (fptr_output == NULL)
		{
			printf("Error occured when trying to open the output file\n");

			exit(-1);

		}

		fprintf(fptr_output, "ciphertext:");

		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (A & (0xff << (i * 8))) >> (i * 8));
			i++;
		}
		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (B & (0xff << (i * 8))) >> (i * 8));
			i++;
		}
		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (C & (0xff << (i * 8))) >> (i * 8));
			i++;
		}
		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (D & (0xff << (i * 8))) >> (i * 8));
			i++;
		}
		fclose(fptr_output);
}


//Decryption function for calling the RC6 encryption implementation

int Decryption(int argc, char** argv)
{
	//Obtain the value of A, B, C, D

		A = 0x0;

		B = 0x0;

		C = 0x0;

		D = 0x0;

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			A = A | (unsigned_var << (i * 8));
		i++;
		}

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			B = B | (unsigned_var << (i * 8));
		i++;
		}

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			C = C | (unsigned_var << (i * 8));
		i++;
		}

		i=0;
		while(i<(W/8)){
			fscanf(fptr_input, "%x", &unsigned_var);

			D = D | (unsigned_var << (i * 8));
		i++;
		}

//Key scheduling algorithm for saving the userkey into the L[] array

		KeySchedule();




//Compute the value for S[0,1,2 .... 2r + 3]

		i=0;
		while(i<(2*R+4)){

			S[i]=0;
			i++;

		}

		S[0] = pw;

		i=1;
		while(i<(2*R+4))
		{
		S[i]=S[i-1]+qw;
		i++;
		}

		Sa = 0;

		Sb = 0;

		Si = 0;

		Sj = 0;
		if(c>2*R+4)
		{
			Sv = 3 * c;
		}
		else
		{
			Sv = 3 * (2*R+4);
		}

		i=1;
		while(i<=Sv){
			Sa = S[Si] = rotl((S[Si] + Sa + Sb), 3);

			Sb = L[Sj] = rotl((L[Sj] + Sa + Sb), (Sa + Sb));

			Si = (Si + 1) % (2 * R + 4);

			Sj = (Sj + 1) % c;

			i++;
		}

//RC6 implementation for Decryption function

		RC6DecBlock(argc,argv);

}



//Function for RC6 Decryption implementation

int RC6DecBlock(int argc, char** argv)
{
	//RC6 implementation for decrypting the ciphertext

		C = C - S[2 * R + 3];

		A = A - S[2 * R + 2];

		i=R;
			while (i >= 1){

			unsigned_var = D;

			D = C;

			C = B;

			B = A;

			A = unsigned_var;

			u = rotl((D * (2 * D + 1)), lgw);

			t = rotl((B * (2 * B + 1)), lgw);

			C = rotr((C - S[2 * i + 1]), (t & 0x1f)) ^ u;

			A = rotr((A - S[2 * i]), (u & 0x1f)) ^ t;

			i--;
		}

		D = D - S[1];

		B = B - S[0];

		fptr_output = fopen(argv[argc - 1], "w");

		if (fptr_output == NULL)

		{

			printf("Error opening the output file\n");

			exit(-1);

		}

		fprintf(fptr_output, "plaintext: ");

		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (A & (0xff << (i * 8))) >> (i * 8));
		i++;
		}

		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (B & (0xff << (i * 8))) >> (i * 8));
		i++;
		}

		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (C & (0xff << (i * 8))) >> (i * 8));
		i++;
		}

		i=0;
		while(i < (W / 8)){

			fprintf(fptr_output, "%.2x ", (D & (0xff << (i * 8))) >> (i * 8));
		i++;
		}

		fclose(fptr_output);

}




//Main function which calls encryption and decrytpion function

int main(int argc, char** argv){
/*
//	FILE *fptr_input, *fptr_output;

	char type_of_op[80];

	char temp_var[80];

	int type_flag;

	int b, c;

	unsigned int unsigned_var;

	unsigned int L[keylength / 4];

	unsigned int S[2 * R + 4];

	unsigned int t, u;

	int i;

	unsigned int Sa, Sb, Si, Sj;

	int Sv;

	unsigned int A, B, C, D;

	unsigned_var = 0;
*/
//Handling the number of the arguments given in the copmmend line

	if (argc != 3){

		printf("Invalid number of parameters\n");

		exit(-1);

	}

//Opening the input file for reading the plaintext

	fptr_input = fopen(argv[argc - 2], "r");

	if (fptr_input == NULL)

	{
		printf("Input file couldn't be opened\n");

		exit(-1);

	}

//Identify from the text whether to encrypt or decrypt

	fscanf(fptr_input, "%s", type_of_op);

	type_flag = -1;
if (strcmp(type_of_op, "Encryption") == 0){
		type_flag = 0;
	}
	else if (strcmp(type_of_op, "Decryption") == 0){
		type_flag = 1;
	}

//Encryption of the plaintext identified from the previous operation

		if(type_flag==0){

		fscanf(fptr_input, "%s", temp_var);

	if ((strcmp(type_of_op, "plaintext") == 0)||(strcmp(type_of_op, "plaintext:") == 0)){
		printf("\nError in the input file content");
		fclose(fptr_input);
		exit(-1);

	}
	else
	{
		Encryption(argc,argv);
	}

		}

//Decryption using RC6 implementation

else if(type_flag==1){


		fscanf(fptr_input, "%s", temp_var);

			if ((strcmp(type_of_op, "ciphertext") == 0)||(strcmp(type_of_op, "ciphertext:") == 0)){

				printf("\nError in the input file content");
		fclose(fptr_input);
		exit(-1);

			}
			else
			{
				Decryption(argc,argv);
			}


}
else
//Handling the arguments and the errors
{
		printf("Invalid file representation or formatting of file.\n");

		fclose(fptr_input);

		exit(-1);
}
	return 0;

}
