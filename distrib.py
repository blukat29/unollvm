import argparse
import gettext
import json
import sys

import celery
import pymongo

import unollvm
from unollvm import tasks
from unollvm.celery import app
from unollvm.util import patch_elf


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

    db = pymongo.MongoClient('mongodb://localhost:27017', connect=False).unollvm

    if args.all:
        h = tasks.upload_binary(input_)
        chain = celery.chain(
                tasks.cfg.si(h),
                tasks.unflatten_all.si(h)
        )
        r = chain()
        chord_id = r.get()
        app.AsyncResult(chord_id).get()

        patches = {}
        for doc in db.patch.find({'binary': h}):
            patches.update(json.loads(doc['patch']))
        patch_elf(input_, output, patches, 0)

    else:
        h = tasks.upload_binary(input_)
        addr_args = map(lambda a: (h, int(a, 16)), args.addr)
        name_args = map(lambda n: (h, n), args.name)

        chain = celery.chain(
                tasks.cfg.si(h),
                celery.group(
                    tasks.unflatten_addr.starmap(addr_args),
                    tasks.unflatten_name.starmap(name_args)
                )
        )
        r = chain()
        r = r.get()

        patches = {}
        for h, addr in addr_args:
            doc = db.patch.find_one({'binary': h, 'addr': addr})
            patches.update(json.loads(doc['patch']))
        for h, name in name_args:
            doc = db.patch.find_one({'binary': h, 'name': name})
            patches.update(json.loads(doc['patch']))
        patch_elf(input_, output, patches, 0)
