"""Version ordering per OSV ecosystem, for the offline matching of tools/devsecops/policy_gate.py (G-02).

Each comparator returns -1, 0 or 1, or raises Unparseable when it cannot read a version: the caller then counts the
component as AFFECTED (fail closed), never as safe. Ecosystems without a comparator here (RubyGems, Packagist and any
other) are matched only by the record's explicit `versions` list; a range on them counts as affected.

- SEMVER (and npm, NuGet, crates.io, Hex, Pub, Go): semantic versioning 2.0.0 — `+build` is ignored, a pre-release is
  lower than the release, pre-release identifiers compare numerically or lexically. Go strips a leading `v`; NuGet and
  Pub allow a fourth numeric part; missing minor/patch read as 0.
- Maven: the order of Maven's ComparableVersion — numbers > qualifiers; alpha < beta < milestone < rc (= cr) <
  snapshot < release (= "", ga, final) < sp < any unknown qualifier (unknown ones lexically). `31.0-jre` > `31.0`.
  A hyphen followed by a digit (`1-1`, timestamped snapshots) is a sub-list there: unreadable here (affected).
- NuGet: semver with the pre-release compared without case.
- PyPI: PEP 440 — epoch, release, pre (a/b/rc), post, dev and local segments (local is ignored for ordering).
"""
import re


class Unparseable(ValueError):
    pass


def _cmp(a, b):
    return (a > b) - (a < b)


# ---- semantic versioning

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_parts(v):
    m = _SEMVER.match(v.strip())
    if not m:
        raise Unparseable(v)
    core = tuple(int(x or 0) for x in m.group(1, 2, 3, 4))
    pre = m.group(5)
    return core, (pre.split(".") if pre else None)


def semver(a, b):
    (ca, pa), (cb, pb) = _semver_parts(a), _semver_parts(b)
    if ca != cb:
        return _cmp(ca, cb)
    if pa is None or pb is None:
        return _cmp(pa is None, pb is None)       # no pre-release is higher
    for x, y in zip(pa, pb):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return _cmp(int(x), int(y))
        if xn != yn:
            return -1 if xn else 1                # numeric identifiers are lower than alphanumeric
        return _cmp(x, y)
    return _cmp(len(pa), len(pb))


def nuget(a, b):
    # NuGet compares pre-release labels without case (1.0.0-RC1 == 1.0.0-rc1).
    return semver(a.lower(), b.lower())


def go(a, b):
    return semver(a.removesuffix("+incompatible"), b.removesuffix("+incompatible"))


# ---- Maven

_MAVEN_RANK = {"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6}
_MAVEN_ALIAS = {"a": "alpha", "b": "beta", "m": "milestone", "cr": "rc", "ga": "", "final": "", "release": ""}


def _maven_items(v):
    v = v.strip().lower()
    if not v or not re.fullmatch(r"[0-9a-z._+-]+", v):
        raise Unparseable(v)
    # A hyphen followed by a digit opens a sub-list in ComparableVersion (`1-1` < `1.0.1`), which this flat model
    # does not reproduce: unreadable here, so the caller counts it as affected.
    if re.search(r"-\d", v):
        raise Unparseable(v)
    tokens = re.findall(r"\d+|[a-z]+", v)
    items = []
    for i, t in enumerate(tokens):
        if t.isdigit():
            items.append((1, int(t)))
        else:
            nxt_digit = i + 1 < len(tokens) and tokens[i + 1].isdigit()
            t = _MAVEN_ALIAS.get(t, t) if (t not in ("a", "b", "m") or nxt_digit) else t
            items.append((0, t))
    while items and items[-1] in ((1, 0), (0, "")):   # 1.0.0 == 1 == 1-ga
        items.pop()
    return items


def _maven_item(x, y):
    if x is None:
        x = (0, "") if y[0] == 0 else (1, 0)
    if y is None:
        y = (0, "") if x[0] == 0 else (1, 0)
    if x[0] != y[0]:
        return 1 if x[0] == 1 else -1                 # a number is greater than a qualifier
    if x[0] == 1:
        return _cmp(x[1], y[1])
    rx, ry = _MAVEN_RANK.get(x[1], 7), _MAVEN_RANK.get(y[1], 7)
    return _cmp(rx, ry) if rx != ry or rx != 7 else _cmp(x[1], y[1])


def maven(a, b):
    ia, ib = _maven_items(a), _maven_items(b)
    for i in range(max(len(ia), len(ib))):
        c = _maven_item(ia[i] if i < len(ia) else None, ib[i] if i < len(ib) else None)
        if c:
            return c
    return 0


# ---- PEP 440

_PEP440 = re.compile(r"""^v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$""", re.X | re.I)
_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_INF = float("inf")


def _pep440_key(v):
    m = _PEP440.match(v.strip())
    if not m:
        raise Unparseable(v)
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = (_PRE[m.group("pre_l").lower()], int(m.group("pre_n") or 0)) if m.group("pre_l") else None
    post_n = m.group("post_n1") or m.group("post_n2")
    post = int(post_n or 0) if (m.group("post_n1") or m.group("post_l")) else None
    dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
    # packaging's ordering: a dev release without pre/post sorts before any pre-release of the same release.
    pre_key = (-_INF,) if pre is None and post is None and dev is not None else ((_INF,) if pre is None else pre)
    post_key = (-_INF,) if post is None else (post,)
    dev_key = (_INF,) if dev is None else (dev,)
    return (int(m.group("epoch") or 0), tuple(release), pre_key, post_key, dev_key)


def pep440(a, b):
    return _cmp(_pep440_key(a), _pep440_key(b))


COMPARATORS = {"SEMVER": semver, "npm": semver, "NuGet": nuget, "crates.io": semver, "Hex": semver, "Pub": semver,
               "Go": go, "Maven": maven, "PyPI": pep440}


def comparator(range_type, ecosystem):
    """The comparator of a range, or None when it is not understood (the caller counts that as affected)."""
    if range_type == "SEMVER":
        return semver
    if range_type == "ECOSYSTEM":
        return COMPARATORS.get(ecosystem)
    return None
