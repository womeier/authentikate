#!/usr/bin/env python3
"""Lift two functions out of the adapters into a standalone test module.

The point of extracting rather than copying is that the test runs the code
that ships.  A copy would pass forever after the originals changed.
"""
import sys

def grab(path, name):
    s = open(path).read()
    i = s.index("(func $%s " % name)
    depth = 0
    for j in range(i, len(s)):
        if s[j] == '(':
            depth += 1
        elif s[j] == ')':
            depth -= 1
            if depth == 0:
                return s[i:j + 1]
    raise SystemExit("unbalanced parens in %s" % path)

out = sys.argv[1]
fns = [
    grab('components/service/adapters/argon2.wat', 'read_N')
        .replace('(func $read_N', '(func (export "read_N")'),
    grab('components/service/adapters/store.wat', 'utf8_ok')
        .replace('(func $utf8_ok', '(func (export "utf8_ok")'),
]
with open(out, 'w') as f:
    f.write('(module\n (memory (export "mem") 1)\n%s\n)\n' % '\n'.join(fns))
