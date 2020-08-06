#!/usr/bin/env python3.8

import dis
import os


def shell(x):
    import os
    os.system('sh')


def main():
    print('Disassembled shell-poping bytecode:', end='\n\n')
    dis.dis(shell.__code__)
    print()

    print('Rendered as CodeType args:', end='\n\n')
    code_args = ''
    code_args += '('
    code_args += repr(shell.__code__.co_argcount)
    code_args +=  ','
    code_args += repr(shell.__code__.co_kwonlyargcount)
    code_args +=  ','
    code_args += repr(shell.__code__.co_posonlyargcount)
    code_args +=  ','
    code_args += repr(shell.__code__.co_nlocals)
    code_args +=  ','
    code_args += repr(shell.__code__.co_stacksize)
    code_args +=  ','
    code_args += repr(shell.__code__.co_flags)
    code_args +=  ','
    code_args += repr(shell.__code__.co_code)
    code_args +=  ','
    code_args += repr(shell.__code__.co_consts)
    code_args +=  ','
    code_args += repr(shell.__code__.co_names)
    code_args +=  ','
    code_args += repr(shell.__code__.co_varnames)
    code_args +=  ','
    code_args += repr(shell.__code__.co_filename)
    code_args +=  ','
    code_args += repr(shell.__code__.co_name)
    code_args +=  ','
    code_args += repr(shell.__code__.co_firstlineno)
    code_args +=  ','
    code_args += repr(shell.__code__.co_lnotab)
    code_args +=  ','
    code_args += repr(shell.__code__.co_freevars)
    code_args +=  ','
    code_args += repr(shell.__code__.co_cellvars)
    code_args += ')'
    print(code_args)


if __name__ == '__main__':
    main()
