#include <stdio.h>



int main(void)
{
    char nom[12];

    printf("name = ?\n");
    gets(nom);
    printf("name is %s\n", nom);

    return 0;
}
