int go(int n)
{
    if (n % 3 == 0) return n + 1;
    else if (n % 3 == 1) return n * 2;
    else return n * n;
}

int main()
{
    go(1);
    return 0;
}
