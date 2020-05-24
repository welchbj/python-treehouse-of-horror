#!/usr/bin/env python3.8

import ast
import atexit
import os
import random
import shlex
import signal
import subprocess
import sys
import time

HEX_CHARS = '0123456789abcdef'


def rand_hex():
    return ''.join([
        random.choice(HEX_CHARS) for _ in range(16)
    ])


ROOT_DIR = os.path.join('/tmp/file-manager-0.1', rand_hex())
KEYS_DIR = os.path.join(ROOT_DIR, 'keys')
DATA_DIR = os.path.join(ROOT_DIR, 'data')


def run(cmd):
    return subprocess.check_output(cmd, shell=True)


class FileStore:
    def __init__(self):
        run(f'mkdir -p {ROOT_DIR}')
        run(f'mkdir -p {KEYS_DIR}')
        run(f'mkdir -p {DATA_DIR}')

    def store_literal(self, *args):
        if len(args) != 2:
            print('USAGE:   store_literal <NAME> <LITERAL>')
            print('EXAMPLE: store_literal my_value "[1,2,3]"')
            return

        name = args[0]
        data = ast.literal_eval(args[1])

        key_file = os.path.join(KEYS_DIR, name)
        data_file = os.path.join(DATA_DIR, rand_hex())

        self.assert_safe_path(key_file)

        with open(data_file, 'w') as f:
            f.write(str(data))

        try:
            os.symlink(data_file, key_file)
        except Exception:
            print('ERROR: Unable to create key file symlink')

    def retrieve_literal(self, *args):
        if len(args) != 1:
            print('USAGE:   retrieve_literal <NAME>')
            print('EXAMPLE: retrieve_literal my_value')
            return

        name = args[0]
        key_file = os.path.join(KEYS_DIR, name)

        self.assert_safe_path(key_file)

        with open(key_file) as f:
            data = f.read()

        print(eval(data))

    def assert_safe_path(self, path, parent=ROOT_DIR):
        norm_path = os.path.normpath(path)
        if not norm_path.startswith(parent):
            raise ValueError('Nice try, hacker')


FS = FileStore()


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
        store_literal=FS.store_literal,
        retrieve_literal=FS.retrieve_literal,
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

            tokens = shlex.split(line)
            if not tokens:
                continue

            func = tokens[0]
            args = tokens[1:]

            funcs.get(func, print_help)(*args)
    except ValueError as e:
        print('ERROR:', e)
        return 1
    except (EOFError, KeyboardInterrupt,):
        pass
    except Exception as e:
        print('Unhandled exception!')
        raise e

    return 0


if __name__ == '__main__':
    sys.exit(main())
