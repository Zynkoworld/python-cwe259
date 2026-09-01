"""python-cwe259 -- hard-coded credential, with module-level constant propagation.

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff the given line assigns a non-empty, non-placeholder
string literal to a credential-like name, or passes one as a credential-like keyword argument. The
value may be the literal itself OR a name bound to a string constant assigned elsewhere in the file, so
`PW = "hunter2"` ... `connect(password=PW)` is decided on the line that uses it.

SAFE when the value comes from the environment or configuration (os.environ, os.getenv, config.get,
getpass), or is an empty string / recognized placeholder. stdlib `ast` only; no code is executed.
NO-VIRUS: the Bandit rule was re-implemented from its description; Bandit is not installed or run.
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


def _origin(call, binds, local):
    """A hivott dolog KOTES szerinti teljes neve. None = nem eldontheto. '<local>.' = sajat definicio."""
    f = call.func
    if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr" \
            and len(f.args) == 2 and isinstance(f.args[1], ast.Constant) \
            and isinstance(f.args[1].value, str):
        base = _dotted(f.args[0])
        return _resolve(base + "." + f.args[1].value, binds) if base else None
    d = _dotted(f)
    if d is None:
        return None
    head = d.split(".")[0]
    if head in local and head not in binds:
        return "<local>." + d
    return _resolve(d, binds)


def _const_strs(tree):
    """Egyszeru `NEV = <string/bytes literal>` ertekadasok BARHOL a fajlban.

    FONTOS es szandekosan kimondva: ez NEM scope-erzekeny -- egy fuggvenyen BELULI ertekadas is
    bekerul, es igy egy masik fuggvenyben szereplo AZONOS NEVU valtozora is ervenyesnek latszik.
    Ez tudatos TUL-KOZELITES a rejtett literal fele; az arat a known_limitations.jsonl rogziti.
    """
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, (str, bytes)):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = n.value.value
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
