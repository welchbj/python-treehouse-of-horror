#!/usr/bin/env python3.8

"""
Slightly updated version of the script published at:
https://nedbatchelder.com/blog/201302/finding_python_3_builtins.html
"""

MAX_ATTR_DEPTH = 10


def is_builtins(obj):
    """Does obj seem to be the builtins?"""
    if hasattr(obj, 'open') and hasattr(obj, '__import__'):
        return True
    elif isinstance(obj, dict):
        return 'open' in obj and '__import__' in obj

    return False


def construct_some(cls):
    """Construct objects from the specified class.

    Yields (obj, attr_path) tuples.

    """
    # First yield the class itself.
    cls_attr_path = f'{cls.__module__}.{cls.__name__}'
    yield cls, cls_attr_path

    made = False
    for args in [
        tuple(), ('x',), ('x', 'y'), ('x', 'y', 'z'),
        ('utf8',), ('os',), (1, 2, 3),
        (0,0,0,0,0,b'KABOOM',(),(),(),'','',0,b''),
        # Maybe there are other useful constructor args?
    ]:
        try:
            obj = cls(*args)
        except:
            continue
        attr_path = f'{cls_attr_path}{args}'
        yield obj, attr_path
        made = True

    if not made:
        print(f"Couldn't make a {cls.__qualname__}")


def iter_members(obj):
    try:
        for field in dir(obj):
            if field == '__dict__':
                continue
            try:
                yield field, getattr(obj, field)
            except:
                continue
    except:
        pass


def iter_items(obj):
    """Produce a sequence of (key, value), if the object supports it."""
    try:
        yield from obj.items()
    except:
        pass


def iter_attrs_and_items(obj, attr_path):
    for attr_name, attr_value in iter_members(obj):
        full_attr_path = f'{attr_path}.{attr_name}'
        yield attr_name, attr_value, full_attr_path

    for key, val in iter_items(obj):
        full_attr_path = f'{attr_path}[{key!r}]'
        yield key, val, full_attr_path


def explore(obj, attr_path, seen, depth):
    """Examine the data reachable from `obj`, looking for builtins."""
    if depth > MAX_ATTR_DEPTH:
        return
    elif id(obj) in seen:
        return
    elif isinstance(obj, (str, bytes, bytearray,)):
        return

    seen.add(id(obj))

    for attr_name, attr_value, full_attr_path in iter_attrs_and_items(obj, attr_path):
        if is_builtins(attr_value):
            print(f'Looks like {full_attr_path} might be builtins')
        else:
            explore(attr_value, full_attr_path, seen, depth + 1)


def main():
    num_examined = 0
    for cls in object.__subclasses__():
        seen = set()
        for obj, attr_path in construct_some(cls):
            print(f'Examining {attr_path}')
            explore(obj, attr_path, seen, 0)
        num_examined += len(seen)

    print(f'Examined {num_examined} objects')


if __name__ == '__main__':
    main()
