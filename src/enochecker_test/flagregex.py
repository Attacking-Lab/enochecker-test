"""Generate a random string matching a supported subset of regex syntax.

Flag regexes used by real checkers are almost always this simple: a literal
prefix/suffix and one or two bounded character classes (e.g.
``ENO[A-Za-z0-9+/=]{48}``). This module parses exactly that subset --
literals, escaped literals, non-negated character classes (with ranges and
the ``\\d``/``\\w``/``\\s`` shorthands), grouping (capturing, ``(?:...)``,
possibly nested), alternation (``|``), and the quantifiers ``?``, ``*``,
``+``, ``{n}``, ``{n,m}``, ``{n,}`` -- and raises `UnsupportedRegexError` for
anything past that (``.``, negated classes, backreferences, lookaround,
mid-pattern anchors, ...), so the caller can fall back to a default shape.
"""

import secrets

# The flag shape most enochecker checkers use; also the fallback shape when a
# given regex falls outside the subset this module supports.
DEFAULT_FLAG_REGEX = r"ENO[A-Za-z0-9+\/=]{48}"

# Caps the length contributed by an unbounded quantifier (`*`, `+`, `{n,}`)
# so a pathological pattern can't generate an absurdly long flag.
MAX_UNBOUNDED_REPEAT = 32

_SHORTHAND_CLASSES = {
    "d": "0123456789",
    "w": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    "s": " \t",
}


class UnsupportedRegexError(ValueError):
    """The pattern uses regex syntax outside the supported subset."""


# AST nodes:
#   ("class", tuple_of_chars)      -- one char, drawn from the given options
#   ("concat", [node, ...])
#   ("alt", [node, ...])
#   ("repeat", node, min, max)


class _Parser:
    def __init__(self, pattern: str):
        self.s = pattern
        self.i = 0
        self.n = len(pattern)

    def peek(self) -> str | None:
        return self.s[self.i] if self.i < self.n else None

    def parse(self):
        # Anchors only make sense at the very start/end of the whole pattern
        # (not per-group), so strip them from the raw string up front rather
        # than treating '^'/'$' as atoms the recursive descent has to special-case.
        s = self.s.removeprefix("^")
        if s.endswith("$") and not s.endswith("\\$"):
            s = s[:-1]
        self.s, self.i, self.n = s, 0, len(s)

        node = self._alt()
        if self.i != self.n:
            raise UnsupportedRegexError(f"unexpected input at offset {self.i}")
        return node

    def _alt(self):
        branches = [self._concat()]
        while self.peek() == "|":
            self.i += 1
            branches.append(self._concat())
        return branches[0] if len(branches) == 1 else ("alt", branches)

    def _concat(self):
        parts = []
        c = self.peek()
        while c is not None and c not in "|)":
            parts.append(self._quantified())
            c = self.peek()
        return parts[0] if len(parts) == 1 else ("concat", parts)

    def _quantified(self):
        atom = self._atom()
        c = self.peek()
        if c == "*":
            self.i += 1
            return ("repeat", atom, 0, MAX_UNBOUNDED_REPEAT)
        if c == "+":
            self.i += 1
            return ("repeat", atom, 1, MAX_UNBOUNDED_REPEAT)
        if c == "?":
            self.i += 1
            return ("repeat", atom, 0, 1)
        if c == "{":
            bounds = self._try_parse_braces()
            if bounds is not None:
                lo, hi = bounds
                return ("repeat", atom, lo, hi)
        return atom

    def _try_parse_braces(self):
        """Parse {n}, {n,m} or {n,} at self.i (a '{'), or return None if it
        isn't one of those (in which case the '{' is left unconsumed and
        _atom will reject it as an unsupported literal metacharacter)."""
        j = self.s.find("}", self.i)
        if j == -1:
            return None
        body = self.s[self.i + 1 : j]
        if "," in body:
            lo_s, _, hi_s = body.partition(",")
            if not lo_s.isdigit():
                return None
            lo = int(lo_s)
            if hi_s == "":
                hi = lo + MAX_UNBOUNDED_REPEAT
            elif hi_s.isdigit():
                hi = int(hi_s)
            else:
                return None
        else:
            if not body.isdigit():
                return None
            lo = hi = int(body)
        self.i = j + 1
        return (lo, hi)

    def _atom(self):
        c = self.peek()
        if c is None:
            raise UnsupportedRegexError("unexpected end of pattern")
        if c == "(":
            self.i += 1
            if self.s[self.i : self.i + 2] == "?:":
                self.i += 2
            elif self.peek() == "?":
                raise UnsupportedRegexError("unsupported group syntax")
            node = self._alt()
            if self.peek() != ")":
                raise UnsupportedRegexError("unbalanced parenthesis")
            self.i += 1
            return node
        if c == "[":
            return self._char_class()
        if c == "\\":
            return self._escape()
        if c in ".^$*+?{}|)":
            raise UnsupportedRegexError(f"unsupported metacharacter {c!r}")
        self.i += 1
        return ("class", (c,))

    def _escape(self):
        self.i += 1
        c = self.peek()
        if c is None:
            raise UnsupportedRegexError("trailing backslash")
        self.i += 1
        if c in _SHORTHAND_CLASSES:
            return ("class", tuple(_SHORTHAND_CLASSES[c]))
        if c.isalnum():
            raise UnsupportedRegexError(f"unsupported escape sequence \\{c}")
        return ("class", (c,))

    def _char_class(self):
        self.i += 1  # skip '['
        if self.peek() == "^":
            raise UnsupportedRegexError("negated character classes are unsupported")
        chars: list[str] = []
        first = True
        while True:
            c = self.peek()
            if c is None:
                raise UnsupportedRegexError("unterminated character class")
            if c == "]" and not first:
                self.i += 1
                break
            first = False
            if c == "\\":
                self.i += 1
                esc = self.peek()
                if esc is None:
                    raise UnsupportedRegexError("trailing backslash in class")
                self.i += 1
                if esc in _SHORTHAND_CLASSES:
                    chars.extend(_SHORTHAND_CLASSES[esc])
                    continue
                c = esc
            else:
                self.i += 1
            if self.peek() == "-" and self.s[self.i + 1 : self.i + 2] not in (
                "",
                "]",
            ):
                self.i += 1  # skip '-'
                end = self.s[self.i]
                self.i += 1
                if end == "\\":
                    end = self.s[self.i]
                    self.i += 1
                if ord(end) < ord(c):
                    raise UnsupportedRegexError("invalid character range")
                chars.extend(chr(o) for o in range(ord(c), ord(end) + 1))
            else:
                chars.append(c)
        if not chars:
            raise UnsupportedRegexError("empty character class")
        return ("class", tuple(dict.fromkeys(chars)))


def _generate(node) -> str:
    kind = node[0]
    if kind == "class":
        return secrets.choice(node[1])
    if kind == "concat":
        return "".join(_generate(part) for part in node[1])
    if kind == "alt":
        return _generate(secrets.choice(node[1]))
    if kind == "repeat":
        _, inner, lo, hi = node
        count = lo if lo == hi else lo + secrets.randbelow(hi - lo + 1)
        return "".join(_generate(inner) for _ in range(count))
    raise AssertionError(f"unknown AST node kind {kind!r}")  # pragma: no cover


def generate_from_regex(pattern: str) -> str:
    """Generate a random string matching `pattern`.

    Raises `UnsupportedRegexError` if `pattern` uses regex syntax outside the
    supported subset (see module docstring).
    """
    return _generate(_Parser(pattern).parse())
