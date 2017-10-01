import argparse
import sys
import gettext

import unollvm


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help(sys.stderr)
        self.exit(2, gettext.gettext('%s: error: %s\n') % (self.prog, message))

if __name__ == '__main__':
    usage = '%(prog)s [-h] [-a] [-v] input output -d [ADDR [ADDR ...]] -n [NAME [NAME ...]]'
    epilog = 'example: python %(prog)s input output -d 401000 4010e8 -n main check'
    parser = ArgumentParser(usage=usage, epilog=epilog)
    parser.add_argument('input', type=argparse.FileType('r'),
            help='Original executable file name')
    parser.add_argument('output', type=argparse.FileType('wb'),
            help='Patched output file name')
    parser.add_argument('-d', '--addr', type=str, nargs='*', default=[],
            help='Addresses of the functions to patch, in hexadecimal')
    parser.add_argument('-n', '--name', type=str, nargs='*', default=[],
            help='Names of the functions to patch')
    parser.add_argument('-a', '--all', action='store_true',
            help='Patch all functions in the file')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    input_ = args.input.name
    args.input.close()
    output = args.output.name
    args.output.close()

    do = unollvm.Deobfuscator(input_, verbose=args.verbose)
    if args.all:
        do.analyze_all()
    else:
        for addr in args.addr:
            do.analyze_addr(int(addr, 16))
        for name in args.name:
            do.analyze_name(name)
    do.commit(output)
