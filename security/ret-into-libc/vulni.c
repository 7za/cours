#include <stdio.h>

void f1(void)
{
	char nom[12];
	int x;

	printf("name = ?\n");
	gets(nom);
}

int main(void)
{
	f1();
	puts("end of file");
	return 0;
}
