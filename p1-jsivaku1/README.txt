NAME: JAYANTH SIVAKUMAR
B-NUMBER: B00615297
B-MAIL ID: jsivaku1@binghamton.edu

YES the code was tested on bingsuns

TO EXECUTE THE PROGRAM:
To Compile: make
To Run: ./Rc6 <inputfile> <outputfile>

Example:
./Rc6 input.txt output.txt

NOTE TO TA
Plaintext, Ciphertext, userkey should be in the format


input.txt
Encryption
plaintext: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
userkey: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


output.txt
Decryption
ciphertext: 8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e
userkey: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


The above format will help the program to generate the correct result for the program.

The RC6 implementation in C will allow the user to enter the plain text in input.txt and generate a ciphertext using this algorithm in output.txt. The program will call a main 
function of Rc6.c, so that encryption and decryption operation will be called in this function. The flag variable is being set so that based on the input file, the type of operation 
will be selected. The plain text will first be stored in the array S[].The user key will be saved in L[]. The RC6 algorithm as given in the paper is implemented as it is.

