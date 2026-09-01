"""python-cwe259 -- hard-coded password (Bandit B105/B106-ekvivalens, SAJAT ast-implementacio).

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff a megadott soron NEM-URES string-literalt rendelnek
jelszo-jellegu nevhez (password/passwd/pwd/secret/token/api_key/apikey/access_key), VAGY ilyen nevu
kulcsszo-argumentumot adnak at string-literallal. SAFE, ha az ertek kornyezeti valtozobol / configbol
jon (os.environ, os.getenv, config.get, getpass), vagy ures string / placeholder.
stdlib `ast` only. NO-VIRUS: a Bandit szabalya ujraimplementalva, a Bandit NINCS telepitve/futtatva.
"""
import ast

CWE = "CWE-259"
_SECRET_RX = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key", "auth")
_PLACEHOLDER = {"", "none", "null", "changeme", "xxx", "todo", "<password>", "your_password_here"}


def _is_secret_name(name):
    low = str(name or "").lower()
    return any(k in low for k in _SECRET_RX)


def _literal_secret(value):
    """Nem-ures, nem-placeholder string-literal?"""
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return False
    return value.value.strip().lower() not in _PLACEHOLDER


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) != line:
            continue
        # (a) password = "literal"   /  self.password = "literal"
        if isinstance(node, ast.Assign) and _literal_secret(node.value):
            for t in node.targets:
                nm = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else None)
                if _is_secret_name(nm):
                    return "FLAG"
        # (b) connect(password="literal")
        if isinstance(node, ast.Call):
            for kw in (node.keywords or []):
                if _is_secret_name(kw.arg) and _literal_secret(kw.value):
                    return "FLAG"
    return "SAFE"
