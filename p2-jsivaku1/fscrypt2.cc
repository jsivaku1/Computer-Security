#include "fscrypt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


 void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){
	printf("\n-------------------------ENCRYPTION USING CBC MODE--------------------------\n");
	printf("\nEncryption using CBC in fscrypt2.cc\n");
	//Allocate for ciphertext
	unsigned char* result = (unsigned char*) malloc((bufsize + 1));

	//intialize the key 
	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
	BF_set_key(key, BLOCKSIZE, (const unsigned char*) keystr);

	//initalize the initial vector to 0's
	unsigned char iVec[BLOCKSIZE];
	for(int i = 0; i < BLOCKSIZE; i++){
		iVec[i] = 0;
	}

	//Pad the plain text
	int padLength = BLOCKSIZE - (bufsize % (BLOCKSIZE));
	if(!padLength){
  		padLength = BLOCKSIZE;
  	}

  	//Combine the plaintext and padlength
	memset((unsigned char*) plaintext + bufsize - 1, (char) padLength, padLength);

	//Encrypting the plaintext (CBC method)
	BF_cbc_encrypt((const unsigned char*) plaintext, (unsigned char*) result, 
		strlen((const char*) plaintext), key, iVec, BF_ENCRYPT);

	//Remove pad on the plaintext
	((char*) plaintext)[bufsize - 1] = '\0';

	//updating length
	*resultlen = bufsize + padLength;

	//return the ciphertext
	return result;
}


 void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	printf("\n-------------------------DECRYPTION USING CBC MODE--------------------------\n");

	printf("\nDecryption using CBC in fscrypt2.cc\n");

	//Allocate for plaintext
	unsigned char* result = (unsigned char*) malloc((bufsize + 1));

	//intialize the key 
	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
	BF_set_key(key, BLOCKSIZE, (const unsigned char*) keystr);

	//initalize the initial vector to 0's
	unsigned char iVec[BLOCKSIZE];
	for(int i = 0; i < BLOCKSIZE; i++){
		iVec[i] = 0;
	}

	//Decrypt the ciphertext (CBC method)

	BF_cbc_encrypt((const unsigned char*) ciphertext, (unsigned char*) result, 
		strlen((const char*) ciphertext), key, iVec, BF_DECRYPT);

	//Remove pad on the ciphertext
	int padLength = result[bufsize - 2];
	result[bufsize - padLength - 1] = '\0';

	//updating length
	*resultlen = (int) strlen((const char*) result) + 1;

	//return the ciphertext
	return result;	
}
