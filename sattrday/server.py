#!/usr/bin/env python3.8

import shlex
import signal
import sys


def alrm_handler(signum, frame):
    print('Time is up!')
    sys.exit()


signal.signal(signal.SIGALRM, alrm_handler)
signal.alarm(60)


def main():
    def safe_eval(code_str):
        return eval(code_str, {'__builtins__': None}, {})

    try:
        while True:
            line = input('> ')

            tokens = shlex.split(line)
            if len(tokens) != 3:
                continue

            target = tokens[0]
            obj = locals()[target]
            attr = tokens[1]
            print('TOKEN:', tokens[2])
            value = safe_eval(tokens[2])
            print('VALUE:', value)

            print(f'[DEBUG]: Setting {obj}.{attr} to {value}')
            setattr(obj, attr, value)
    except (EOFError, KeyboardInterrupt,):
        pass
    except Exception as e:
        print('Unhandled exception!')
        raise e

    return 0


if __name__ == '__main__':
    sys.exit(main())
