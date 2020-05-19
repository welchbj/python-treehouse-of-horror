#!/usr/bin/env python3.8

import code
import signal
import sys

def alrm_handler(signum, frame):
    print('Time is up!')
    sys.exit()

signal.signal(signal.SIGALRM, alrm_handler)
signal.alarm(60)

def handle_input(line):
    if '(' in line or ')' in line:
        return "print('We were pretty clear about no parentheses.')"

    return line

def main():
    banner = """\
Welcome to a Python sandbox so safe, it's exposed on the public internet.
We have one rule and one rule only: no parentheses.

Flag is in /flag and can only be read by executing the /readflag binary.
"""

    exit_msg = 'Good-bye!'

    class X:
        pass

    scope = {
        '__builtins__': {
            'call_me_maybe': os.system,
            'x': X(),
            'exit': sys.exit
        }
    }

    try:
        while True:
            code.interact(banner, handle_input, scope, exit_msg)
    except SystemExit:
        pass

    return 0


if __name__ == '__main__':
    sys.exit(main())

