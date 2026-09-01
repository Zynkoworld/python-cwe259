"""python-cwe259 -- hard-coded credential, with module-level constant propagation.

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the given line assigns a non-empty, non-placeholder
string literal to a credential-like name, or passes one as a credential-like keyword argument. The
value may be the literal itself OR a name bound to a string constant assigned elsewhere in the file, so
`PW = "hunter2"` ... `connect(password=PW)` is decided on the line that uses it.

SAFE when the value comes from the environment or configuration (os.environ, os.getenv, config.get,
getpass), or is an empty string / recognized placeholder. stdlib `ast` only; no code is executed.
NO-VIRUS: the Bandit rule was re-implemented from its description; Bandit is not installed or run.

SCOPE OF CONSTANT FOLDING (declared, so the boundary is visible rather than discovered):
this decider follows a constant through literal concatenation (including multi-step), adjacent string
literals, constant-only f-strings, and case conversion (`.upper()` / `.lower()` -- included because the
algorithm comparison is already case-insensitive, so excluding it would be inconsistent rather than
conservative). Every other way of deriving a constant -- %-formatting, `.format()`, `''.join([...])`,
indexing, unpacking, other string methods -- and a conditional name (`x if c else y`) are OUTSIDE that
scope and are recorded in `probes/known_limitations.jsonl`. The line is drawn by declaration, not by
adding evaluator branches: each extra branch would be one more place to be wrong, for a shrinking
return.
"""
import ast

CWE = "CWE-259"
_SECRET_RX = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key", "auth")
_PLACEHOLDER = {"", "none", "null", "changeme", "xxx", "todo", "<password>", "your_password_here"}
# --- import-kotes feloldas (zafire #19219: a dontes a KOTESRE alljon, ne a nevre) ---

def _dotted(node):
    """a.b.c -> "a.b.c"; barmi mas -> None"""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _resolve(dotted, binds):
    head, _, rest = dotted.partition(".")
    if head in binds:
        return binds[head] + ("." + rest if rest else "")
    return dotted


def _bindings(tree):
    """lokalis nev -> teljes (pontozott) eredet: importok + egyszeru referencia-atadas."""
    binds = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                binds[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom):
            mod = n.module or ""
            for a in n.names:
                binds[a.asname or a.name] = (mod + "." + a.name) if mod else a.name
    for n in ast.walk(tree):          # f = hashlib.md5  ->  f kotese hashlib.md5
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            d = _dotted(n.value)
            if d:
                binds[n.targets[0].id] = _resolve(d, binds)
    return binds


def _local_defs(tree):
    """a modul altal MAGA definialt nevek -- ezek arnyekoljak az azonos nevu konyvtari hivast."""
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
    return out


def _origin(call, binds, local, consts=None):
    """A hivott dolog KOTES szerinti teljes neve. None = nem eldontheto. '<local>.' = sajat definicio.

    A getattr-ag feloldja a konstans attributum-nevet is -- literalkent (`getattr(m, "md5")`) ES
    konstanshoz kotott nevkent (`n = "md5"; getattr(m, n)`). A VALODIAN dinamikus nev (`n = pick()`)
    nem oldhato fel a forrasbol; ott None a valasz, nem tipp.
    """
    f = call.func
    if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr" \
            and "getattr" not in local and len(f.args) >= 2:
        attr = f.args[1]
        name = None
        if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
            name = attr.value
        elif isinstance(attr, ast.Name) and consts and attr.id in consts:
            c = consts[attr.id]
            name = c.decode("utf-8", "replace") if isinstance(c, bytes) else c
        if not isinstance(name, str):
            return None
        base = _dotted(f.args[0])
        return _resolve(base + "." + name, binds) if base else None
    d = _dotted(f)
    if d is None:
        return None
    head = d.split(".")[0]
    if head in local and head not in binds:
        return "<local>." + d
    return _resolve(d, binds)


def _fold_str(node, tbl):
    """Statikusan kihajthato string/bytes ertek, vagy None.

    Kihajtja a konstans-osszefuzest (`'md' + '5'`) es a csak-konstans f-stringet (`f'md{5}'`), es
    feloldja a mar ismert neveket -- de csak azokat, amelyek EDDIG kerultek a tablaba, igy a
    sorrend-tudatos (last-write-wins) viselkedes megmarad.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value
    if isinstance(node, ast.Name):
        return tbl.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _fold_str(node.left, tbl), _fold_str(node.right, tbl)
        if isinstance(a, str) and isinstance(b, str):
            return a + b
        if isinstance(a, bytes) and isinstance(b, bytes):
            return a + b
        return None
    # KIS/NAGYBETU-ATALAKITAS: nem "egy lepessel tovabb kovetjuk a konstanst", hanem kovetkezetesseg
    # egy dontessel, amit a decider mar meghozott -- az algoritmus-nevet amugy is kis/nagybetu-
    # fuggetlenul hasonlitja. Minden EGYEB str-metodus a deklaralt hatokoron KIVUL van.
    if isinstance(node, ast.Call) and not node.args and not node.keywords \
            and isinstance(node.func, ast.Attribute) and node.func.attr in ("upper", "lower"):
        base = _fold_str(node.func.value, tbl)
        if isinstance(base, str):
            return base.upper() if node.func.attr == "upper" else base.lower()
        return None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue) and v.format_spec is None \
                    and v.conversion in (-1, None):
                inner = v.value
                if isinstance(inner, ast.Constant) and isinstance(inner.value, (str, int, float)) \
                        and not isinstance(inner.value, bool):
                    parts.append(str(inner.value))
                else:
                    c = _fold_str(inner, tbl)
                    if not isinstance(c, str):
                        return None
                    parts.append(c)
            else:
                return None
        return "".join(parts)
    return None


def _const_strs(tree):
    """Egyszeru `NEV = <statikusan kihajthato string/bytes>` ertekadasok BARHOL a fajlban.

    Kihajtja a konstans-osszefuzest es a csak-konstans f-stringet is -- egy nev akkor szamit
    ismertnek, ha az ERTEKE a forrasbol kiszamolhato, nem csak ha puszta literal.

    FONTOS es szandekosan kimondva: ez NEM scope-erzekeny -- egy fuggvenyen BELULI ertekadas is
    bekerul, es igy egy masik fuggvenyben szereplo AZONOS NEVU valtozora is ervenyesnek latszik.
    Ez tudatos TUL-KOZELITES a rejtett literal fele; az arat a known_limitations.jsonl rogziti.
    A tabla SORREND-TUDATOS: a kesobbi ertekadas felulirja a korabbit (last-write-wins).
    """
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            v = _fold_str(n.value, out)
            if v is None:
                continue
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = v
    return out


def _is_secret_name(name):
    low = str(name or "").lower()
    return any(k in low for k in _SECRET_RX)


def _secret_value(value, consts):
    """Nem-ures, nem-placeholder string -- literalkent VAGY modul-szintu konstansra hivatkozva."""
    v = None
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        v = value.value
    elif isinstance(value, ast.Name) and value.id in consts:
        c = consts[value.id]
        v = c.decode("utf-8", "replace") if isinstance(c, bytes) else c
    if v is None:
        return False
    return v.strip().lower() not in _PLACEHOLDER


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    consts = _const_strs(tree)
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) != line:
            continue
        if isinstance(node, ast.Assign) and _secret_value(node.value, consts):
            for t in node.targets:
                nm = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else None)
                if _is_secret_name(nm):
                    return "FLAG"
        if isinstance(node, ast.Call):
            for kw in (node.keywords or []):
                if _is_secret_name(kw.arg) and _secret_value(kw.value, consts):
                    return "FLAG"
    return "SAFE"
