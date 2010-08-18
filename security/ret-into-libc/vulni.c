#include <stdio.h>



void f1()
{
    char nom[12];

    printf("name = ?\n");
    gets(nom);
//    printf("name is %s\n", nom);
	getchar();
	sleep(120);
}

int main(void)
{
    f1();
    return 0;
}
