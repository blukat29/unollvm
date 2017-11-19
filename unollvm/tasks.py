from __future__ import absolute_import
import hashlib
import json
import logging
import os
import pickle
import tempfile
import zlib

import angr
import bson
import celery
import keystone
import pymongo

import unollvm

from .celery import app

logging.getLogger('angr.factory').setLevel(logging.WARN)
logging.getLogger('angr.project').setLevel(logging.WARN)
logging.getLogger('cle.loader').setLevel(logging.WARN)
logging.getLogger('unollvm').setLevel(logging.WARN)

db = pymongo.MongoClient('mongodb://localhost:27017', connect=False).unollvm
log = logging.getLogger('unollvm.tasks')
log.setLevel(logging.INFO)

binary_dir = '/tmp/uo/'

def upload_binary(filename):
    with open(filename, 'rb') as f:
        content = f.read()
    sha256 = hashlib.sha256(content).hexdigest()

    binary = db.binary.find_one({'sha256': sha256})
    if not binary:
        key = {'sha256': sha256}
        val = {
            'sha256': sha256,
            'filename': filename,
            'content': bson.binary.Binary(content),
            'cfg_done': False,
        }
        db.binary.update(key, val, upsert=True)
    return sha256

def load_binary(binary):
    filename = os.path.abspath(os.path.join(binary_dir, binary['sha256']))

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

    if binary['cfg_done']:
        log.info('CFG for binary {} exists in DB.'.format(binary_id[:7]))
        functions = db.function.find({'binary': binary_id})
        return list(map(lambda x: int(x['addr']), functions))

    filename, proj = load_binary(binary)

    log.info('Extract CFG binary {}'.format(binary_id[:7]))
    cfg = proj.analyses.CFGFast()
    log.info('Extract CFG binary {} done'.format(binary_id[:7]))

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

    db.binary.update({'sha256': binary_id}, {'$set': {'cfg_done': True}})
    return addrs

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
    else:
        return {}


def unflatten(binary_id, func_addr=None, func_name=None):
    binary = db.binary.find_one({'sha256': binary_id})
    if not binary:
        raise ValueError('Cannot find binary {}'.format(binary_id))

    if func_addr:
        key = {'binary': binary_id, 'addr': str(func_addr)}
    elif func_name:
        key = {'binary': binary_id, 'name': func_name}
    else:
        raise ValueError('Must provide either function address or name')

    function = db.function.find_one(key)
    if not function:
        raise ValueError('Cannot find function 0x{:x} of binary {}'.format(func_addr, binary_id))

    log.info('Unflatten binary {} function {} ({})'.format(
        binary_id[:7], function['name'], hex(int(function['addr']))))

    patches = _unflatten(binary, function)

    log.info('Unflatten binary {} function {} ({}) {}'.format(
        binary_id[:7], function['name'], hex(int(function['addr'])),
        'done' if len(patches) > 0 else 'not flattened'))

    key = {'binary': binary_id, 'addr': function['addr']}
    val = key.copy()
    val.update({'patch': json.dumps(patches)})
    db.patch.update(key, val, upsert=True)
    return patches

@app.task
def unflatten_addr(binary_id, func_addr):
    return unflatten(binary_id, func_addr=func_addr)

@app.task
def unflatten_name(binary_id, func_name):
    return unflatten(binary_id, func_name=func_name)

@app.task
def collect_patches(patches):
    return patches

@app.task
def unflatten_all(addrs, binary_id):
    jobs = (unflatten_addr.s(binary_id, addr) for addr in addrs)
    chord = celery.chord(jobs)(collect_patches.s())
    return chord.id
