#!/usr/bin/env python3.8

import ast
import binascii
import atexit
import os
import pickle
import random
import shlex
import signal
import subprocess
import sys
import time

HEX_CHARS = '0123456789abcdef'


def rand_hex():
    return ''.join([
        random.choice(HEX_CHARS) for _ in range(32)
    ])


def run(cmd):
    return subprocess.check_output(cmd, shell=True)


ROOT_DIR = os.path.join('/tmp/file-manager-0.1', rand_hex())
KEYS_DIR = os.path.join(ROOT_DIR, 'keys')
BLOBS_DIR = os.path.join(ROOT_DIR, 'blobs')
OBJECTS_DIR = os.path.join(ROOT_DIR, 'objects')
run(f'mkdir -p {ROOT_DIR}')
run(f'mkdir -p {KEYS_DIR}')
run(f'mkdir -p {BLOBS_DIR}')
run(f'mkdir -p {OBJECTS_DIR}')


def _store_data(name, raw_data, _type='blobs'):
    key_file = os.path.join(KEYS_DIR, name)
    assert_safe_key_file(key_file)

    data_dir = os.path.join(ROOT_DIR, _type)
    data_file = os.path.join(data_dir, rand_hex())

    with open(data_file, 'wb') as f:
        f.write(raw_data)

    try:
        os.symlink(data_file, key_file)
    except Exception:
        print('ERROR: Unable to create key file symlink')


def _retrieve_data(name):
    key_file = os.path.join(KEYS_DIR, name)
    assert_safe_key_file(key_file)

    with open(key_file, 'rb') as f:
        data = f.read()

    return data


def store_object(*args):
    if len(args) != 2:
        print('USAGE:   store_object <NAME> <LITERAL>')
        print('EXAMPLE: store_object my_value "[1,2,3]"')
        return

    name = args[0]
    try:
        data = ast.literal_eval(args[1])
    except Exception:
        print('ERROR: Unable to parse literal value')
        return

    _store_data(name, pickle.dumps(data), _type='objects')


def retrieve_object(*args):
    if len(args) != 1:
        print('USAGE:   retrieve_object <NAME>')
        print('EXAMPLE: retrieve_object my_value')
        return

    name = args[0]
    data = _retrieve_data(name)
    print(pickle.loads(data))


def store_bytes(*args):
    if len(args) != 2:
        print('USAGE:   store_bytes <NAME> <HEX_ENCODED_BYTES>')
        print('EXAMPLE: store_bytes my_value deadbeef')
        return

    name = args[0]
    try:
        data = binascii.unhexlify(args[1])
    except Exception:
        print('ERROR: Unable to decode hex')
        return

    _store_data(name, data, _type='blobs')


def retrieve_bytes(*args):
    if len(args) != 1:
        print('USAGE:   retrieve_bytes <NAME>')
        print('EXAMPLE: retrieve_bytes my_value')
        return

    name = args[0]
    data = _retrieve_data(name)
    print(binascii.hexlify(data).decode())


def assert_safe_key_file(path, parent=ROOT_DIR):
    norm_path = os.path.normpath(path)
    if not norm_path.startswith(parent):
        raise ValueError('Nice try')
    elif os.path.isfile(norm_path) and not os.path.islink(norm_path):
        raise ValueError('Wow, good try. But not good enough')


def alrm_handler(signum, frame):
    print('Time is up!')
    sys.exit(1)
signal.signal(signal.SIGALRM, alrm_handler)
signal.alarm(60)


def cleanup():
    run(f'rm -rf {ROOT_DIR}')
atexit.register(cleanup)


def main():
    funcs = dict(
        exit=lambda: sys.exit(0),
        store_object=store_object,
        retrieve_object=retrieve_object,
        store_bytes=store_bytes,
        retrieve_bytes=retrieve_bytes,
    )

    def print_help(*args):
        print('Invalid function call! Here are your options:')
        print('\n'.join(sorted(funcs.keys())))

    sys_time = int(time.time())
    print('Welcome to a perfectly secure Python storage system.')
    print('DEBUG: System time is', sys_time)
    random.seed(a=sys_time)

    try:
        while True:
            line = input('> ')

            try:
                tokens = shlex.split(line)
            except Exception:
                print('ERROR: Unable to parse arguments')
                continue

            if not tokens:
                continue

            func = tokens[0]
            args = tokens[1:]

            funcs.get(func, print_help)(*args)
    except ValueError as e:
        print('ERROR:', e)
        return 1
    except FileNotFoundError:
        print('ERROR: Nice try')
        return 1
    except (EOFError, KeyboardInterrupt,):
        pass
    except Exception as e:
        print('Unhandled exception!')
        raise e

    return 0


if __name__ == '__main__':
    sys.exit(main())
