int go(int n)
{
    if (n == 0) return n + 1;
    else if (n == 1) return n * 2;
    else return n * n;
}

int main(int argc, char** argv)
{
    return go(argc);
}
