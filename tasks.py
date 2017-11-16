import hashlib
import logging
import zlib
import os
import pickle
import tempfile
from os import path

import angr
import keystone
import bson
import unollvm
import json
from celery import Celery
from pymongo import MongoClient

app = Celery('unollvm', backend='redis://localhost', broker='redis://localhost')
db = MongoClient('mongodb://localhost:27017').unollvm
logging.getLogger('unollvm').setLevel(logging.INFO)

binary_dir = '/tmp/uo/'

def upload_binary(filename):
    with open(filename, 'rb') as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()

    key = {'sha256': sha256}
    val = {
        'sha256': sha256,
        'filename': filename,
        'content': bson.binary.Binary(content),
    }
    db.binary.update(key, val, upsert=True)
    return sha256

def load_binary(binary):
    filename = path.abspath(path.join(binary_dir, binary['sha256']))

    handle = tempfile.NamedTemporaryFile(delete=False)
    handle.write(binary['content'])
    handle.close()
    os.rename(handle.name, filename)

    load_options = {'auto_load_libs': False}
    proj = angr.Project(filename, load_options=load_options)
    return filename, proj

def pack_object(o):
    o = pickle.dumps(o)
    o = zlib.compress(o)
    return bson.binary.Binary(o)

def unpack_object(o):
    o = zlib.decompress(o)
    return pickle.loads(o)

@app.task
def cfg(binary_id):
    binary = db.binary.find_one({'sha256': binary_id})
    if not binary:
        raise ValueError('Cannot find binary {}'.format(binary_id))

    filename, proj = load_binary(binary)

    cfg = proj.analyses.CFGFast()
    addrs = []
    for addr, func in cfg.functions.iteritems():
        if not (func.is_syscall or func.is_plt or func.is_simprocedure):
            key = {
                'binary': binary_id,
                'addr': str(addr),
            }
            val = {
                'binary': binary_id,
                'addr': str(addr),
                'name': func.name,
                'object': pack_object(func),
                'graph': pack_object(func.transition_graph),
            }
            db.function.update(key, val, upsert=True)
            addrs.append(addr)

    return addr

def _unflatten(binary, function):
    filename, proj = load_binary(binary)
    func = unpack_object(function['object'])
    graph = unpack_object(function['graph'])
    for addr in func.block_addrs:
        func.get_node(addr)._graph = graph

    shape = unollvm.shape.Shape(proj, func)
    if shape.is_ollvm:
        control = unollvm.control.Control(proj, shape)
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        patch = unollvm.patch.Patch(proj, shape, control, ks)

    return patch.patches

@app.task
def unflatten(binary_id, func_addr):
    binary = db.binary.find_one({'sha256': binary_id})
    if not binary:
        raise ValueError('Cannot find binary {}'.format(binary_id))

    function = db.function.find_one({
        'binary': binary_id,
        'addr': str(func_addr)
    })
    if not function:
        raise ValueError('Cannot find function 0x{:x} of binary {}'
                .format(func_addr, binary_id))

    patches = _unflatten(binary, function)

    key = {
        'binary': binary_id,
        'addr': str(func_addr),
    }
    val = {
        'binary': binary_id,
        'addr': str(func_addr),
        'patch': json.dumps(patches)
    }
    db.patch.update(key, val, upsert=True)


if __name__ == '__main__':
    h = upload_binary('./example/call.fla')
    cfg(h)
    unflatten('ebd5f40261e08b5bf121e47c7b8055fd578f399d454fe72f137cea75b9bdd9d7', 4195600)
    exit()
