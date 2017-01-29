#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fscrypt.h"
//=================================ENCRYPTION======================================================
//Encryption function using ECB method

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
	int InBufSize=((bufsize+7)/8*8), i, j, k, keylen;
	BF_KEY *key = (BF_KEY *)malloc(sizeof(BF_KEY));
	unsigned char *Output = (unsigned char*)malloc(sizeof(char) * 8); 
	unsigned char *OutputBuffer = (unsigned char*)malloc(sizeof(char) * InBufSize);
	char *TempText = (char*)malloc(sizeof(char)*bufsize);
	char *textcopy = (char*)plaintext;
	printf("\n-------------------------ENCRYPTION USING ECB MODE-----------------------------\n");
	printf("\nEncryption using ECB mode in the file fscrypt.cc:\n");
	 //Adding the  plaintext into the  TempText

	j=0;
	while(j < bufsize)
	{
		*(TempText + j) = *(textcopy + j);
		j++;
	}

	//Padding the TempText with '\0',counting the InBufSize

	i = bufsize % 8;
	j = 0;
	k = i;
		if (i == 0)
		InBufSize = bufsize /8;
	else
	{
		InBufSize = bufsize / 8 + 1;
		while (i<8)
		{
			*(TempText+bufsize + j) =8-k;
			i++;
			j++;
		}
	}
		*resultlen = InBufSize * 8;
		
		//Calling the SET Key function BF_SET_KEY

		keylen = strlen(keystr) ;
		BF_set_key(key, keylen, (unsigned char*)keystr);

		//ECB function for encryption

		j = 0;
		i = 0;
		while(i<InBufSize*8)
		{
			*(TempText + i) = *(TempText + i) ^ 0;
			i++;
		}

			i = 0;
			while (InBufSize > 0)
			{
				BF_ecb_encrypt((const unsigned char*)TempText + j * 8, Output, key, BF_ENCRYPT);
				//Putting the encrypted texts into output buffer and return OutputBuffer;
				i = 0;
				while(i<8)
				{
					*(OutputBuffer + i+j*8) = *(Output + i);
					i++;
				}
				if (InBufSize == 1)break;
				j++;
				i=0;
				while(i<8)
				{
					*(TempText + i + j * 8)=*(TempText + i + j * 8) ^ *(Output + i);
					i++;
				}
				
				InBufSize--;
			}
		
		return (void*)OutputBuffer;
		free(Output);
}

//================================DECRYPTION=====================================================
//Decryption function using ECB mode

void *fs_decrypt(void *ciphertext,int bufsize,char *keystr,int *resultlen)
{
	int InBufSize=((bufsize+7)/8*8) ,buf, i, j, keylen;
	BF_KEY *key = (BF_KEY *)malloc(sizeof(BF_KEY));
	char *TempCipherText = (char*)malloc(sizeof(char)*bufsize);
	unsigned char *Output = (unsigned char*)malloc(sizeof(char)*8);
	unsigned char *OutputBuffer = (unsigned char*)malloc(sizeof(char)*bufsize);
	int padding;	

	InBufSize = bufsize / 8;
	printf("\n------------------------DECRYPTION USING ECB MODE--------------------------------\n");
	printf("\nDecryption using ECB mode in the file fscrypt.cc:\n");

	//Copy the Cipher text into TempCipherText

	j=0;
	while(j < bufsize)
	{
		*(TempCipherText + j) = *((char*)ciphertext + j);
		j++;
	}
	//calling the  BF_SET_KEY function 

	keylen = strlen(keystr) ;
	BF_set_key(key, keylen, (unsigned char*)keystr);

	//ECB decryption function

	i =j= 0;

		for (j = 0; j < InBufSize;j++)
		{ 
			BF_ecb_encrypt((const unsigned char*)TempCipherText + j * 8, Output, key, BF_DECRYPT);
			if (j == 0)
			{
				i=0;
				while(i<8)
				{
					*(OutputBuffer + i) = *(Output + i)^0; 
					i++;
				}
				continue;
			}
			else
			{
				i=0;
				while(i<8)
				{
					*(OutputBuffer + i + j * 8) = *(Output + i) ^ *(TempCipherText + i + (j - 1) * 8);
					i++;
				}
			}
		}
	
	//Delete the unwanted padded bits from the text

	padding = *(OutputBuffer + bufsize-1);
	char *outbuffer = (char*)malloc((sizeof(char))*(bufsize-padding));
	
	i=0;
	while(i<bufsize-padding)
	{
		*(outbuffer+i)=*(OutputBuffer+i);
		i++;
	}

	*resultlen = bufsize-padding;
	return (void*)OutputBuffer;
}

