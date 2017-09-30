#include <stdio.h>
int main()
{
    unsigned int x = 10;
    while (x--)
    {
        if (x % 2 == 0)
            printf("%d is even\n", x);
        else
            printf("%d is odd\n", x);
    }
}
