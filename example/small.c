int go(int n)
{
    if (n % 3 == 0) return n + 1;
    else if (n % 3 == 1) return n * 2;
    else return n * n;
}

int main(int argc, char** argv)
{
    go(argc);
    return 0;
}
