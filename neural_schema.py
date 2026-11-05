#!/usr/bin/env python3
"""
NeuralSchema  --  Universal Code & System Architecture Analyzer
================================================================

Builds a "neural schema" (an architecture graph of nodes + relations) for:

  1. SOURCE CODE  across many languages
        Python  (.py)          - via the built-in `ast` module
        C       (.c .h)        - via tree-sitter
        C++     (.cpp .hpp ..)  - via tree-sitter
        Java    (.java)        - via tree-sitter
        C#      (.cs)          - via tree-sitter
        Shell   (.sh .bash)    - via tree-sitter  (Bash / sh)
     It extracts modules, namespaces, classes/structs/interfaces, functions,
     methods, imports/includes, inheritance, call-graph edges and (for shell)
     the external programs a script invokes -- perfect for understanding a
     program's structure on a machine (e.g. Ubuntu).

  2. THE OPERATING SYSTEM itself  (live introspection via psutil)
        CPU / memory / disks / network interfaces / logged-in users and a
        process tree (parent->child) of the heaviest processes, with optional
        network-connection nodes.

The result can be:
    - explored interactively in a Tkinter GUI (force-directed graph, click a
      node to inspect it and highlight its neighbours),
    - exported to a self-contained interactive HTML page (works offline),
    - exported to JSON (nodes + edges), or a PNG snapshot.

USAGE
-----
    # Launch the GUI (default when no analysis flags are given):
    python3 neural_schema.py

    # Command line -- analyse a file, a whole project folder, or the OS:
    python3 neural_schema.py --file path/to/program.py
    python3 neural_schema.py --file path/to/project_dir
    python3 neural_schema.py --system --top 50

    # Add exports (any combination), optionally with --no-gui to stay headless:
    python3 neural_schema.py --file src/ --export html json png --out ./schema --no-gui
    python3 neural_schema.py --system --connections --export html --no-gui

    # Crawl Mode -- animated "watch a crawler explore it" page (offline HTML):
    python3 neural_schema.py --file src/ --export crawl --no-gui
    python3 neural_schema.py --url https://example.com/ --strategy replay --export crawl --no-gui

DEPENDENCIES
------------
    pip install psutil networkx matplotlib tree-sitter tree-sitter-language-pack pyvis

Author: built for Kanak. Single-file, no build step. MIT-style, use freely.
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
import json
import socket
import getpass
import datetime
import platform
from collections import defaultdict

# ----------------------------------------------------------------------------
# Optional dependencies -- imported lazily / defensively so a missing extra
# only disables the feature that needs it rather than crashing the whole tool.
# ----------------------------------------------------------------------------
try:
    import networkx as nx
except Exception:  # pragma: no cover
    nx = None

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    import tree_sitter as ts
    from tree_sitter_language_pack import get_language, get_parser
    _TS_OK = True
except Exception:  # pragma: no cover
    ts = None
    _TS_OK = False

try:
    from pyvis.network import Network
    _PYVIS_OK = True
except Exception:  # pragma: no cover
    _PYVIS_OK = False


# ============================================================================
#  Node kinds, relations and their visual styling
# ============================================================================

# --- code kinds ---
K_PROJECT   = "project"
K_MODULE    = "module"
K_NAMESPACE = "namespace"
K_CLASS     = "class"
K_STRUCT    = "struct"
K_INTERFACE = "interface"
K_FUNCTION  = "function"
K_METHOD    = "method"
K_IMPORT    = "import"
K_VARIABLE  = "variable"
K_EXTERNAL  = "external"
K_VULN      = "vulnerability"   # a call to a known-dangerous function (SAST)
K_PORT      = "open_port"       # a process LISTENing on a port

# --- system kinds ---
K_SYSTEM  = "system"
K_CPU     = "cpu"
K_MEMORY  = "memory"
K_DISK    = "disk"
K_NET     = "network"
K_IFACE   = "interface"
K_USER    = "user"
K_PROCESS = "process"
K_CONN    = "connection"

# Colour palette tuned for a dark canvas.
KIND_COLOR = {
    K_PROJECT:   "#f778ba",
    K_MODULE:    "#58a6ff",
    K_NAMESPACE: "#bc8cff",
    K_CLASS:     "#3fb950",
    K_STRUCT:    "#2ea043",
    K_INTERFACE: "#39c5cf",
    K_FUNCTION:  "#ffa657",
    K_METHOD:    "#e3b341",
    K_IMPORT:    "#8b949e",
    K_VARIABLE:  "#c9926b",
    K_EXTERNAL:  "#f85149",
    K_SYSTEM:    "#f0f6fc",
    K_CPU:       "#f85149",
    K_MEMORY:    "#58a6ff",
    K_DISK:      "#d29922",
    K_NET:       "#3fb950",
    K_IFACE:     "#39c5cf",
    K_USER:      "#bc8cff",
    K_PROCESS:   "#ffa657",
    K_CONN:      "#8b949e",
    K_VULN:      "#ff3860",   # crimson  -- danger
    K_PORT:      "#ff9f1c",   # marigold -- exposure
}

# --- relations ---
R_CONTAINS   = "contains"
R_IMPORTS    = "imports"
R_INCLUDES   = "includes"
R_SOURCES    = "sources"
R_CALLS      = "calls"
R_INHERITS   = "inherits"
R_IMPLEMENTS = "implements"
R_PARENT     = "parent"
R_USES       = "uses"
R_RUNS       = "runs"
R_CONNECTS   = "connects"
R_LISTENS    = "listens"
R_DANGER     = "danger-call"

# (edge colour, matplotlib linestyle) for each relation on the dark canvas.
REL_STYLE = {
    R_CONTAINS:   ("#484f58", "solid"),
    R_IMPORTS:    ("#6e7681", "dotted"),
    R_INCLUDES:   ("#6e7681", "dotted"),
    R_SOURCES:    ("#6e7681", "dashed"),
    R_CALLS:      ("#1f6feb", "solid"),
    R_INHERITS:   ("#3fb950", "dashed"),
    R_IMPLEMENTS: ("#39c5cf", "dashed"),
    R_PARENT:     ("#484f58", "solid"),
    R_USES:       ("#6e7681", "solid"),
    R_RUNS:       ("#f85149", "dotted"),
    R_CONNECTS:   ("#8b949e", "dashed"),
    R_LISTENS:    ("#ff9f1c", "dashed"),
    R_DANGER:     ("#ff3860", "solid"),
}

# extension -> tree-sitter / python language key
EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".c": "c",
    ".h": "c_header",            # resolved to c/cpp by a content sniff
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c++": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp",
    ".java": "java",
    ".cs": "csharp",
    ".sh": "bash", ".bash": "bash",
}

# directories to skip when walking a project folder
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", "venv",
             ".venv", "env", "build", "dist", ".idea", ".vscode", "target",
             "bin", "obj", ".mypy_cache", ".pytest_cache"}


# ----------------------------------------------------------------------------
#  Lightweight SAST catalog.
#
#  IMPORTANT: this is a *heuristic smell detector*, not real taint analysis.
#  It flags calls by NAME.  It is strong for C/C++, Bash and Python and much
#  weaker for Java/C# (where only the bare method name is visible, so `exec`
#  is a decent signal but generic names would be noisy).  A hit only means
#  "this deserves a human look", and only fires when the name does NOT resolve
#  to a function the file itself defines (so your own def foo() is never a hit).
#
#  Values are severities: "high" | "medium".  Keys are matched against both the
#  bare call name and, for Python, the dotted call path (e.g. "os.system").
# ----------------------------------------------------------------------------
DANGEROUS = {
    "python": {
        "eval": "high", "exec": "high", "compile": "medium",
        "__import__": "medium",
        "os.system": "high", "os.popen": "high",
        "subprocess.Popen": "high", "subprocess.call": "high",
        "subprocess.run": "high", "subprocess.check_output": "high",
        "pickle.load": "high", "pickle.loads": "high",
        "marshal.loads": "high",
        "yaml.load": "high",
        "input": "medium",                # py2 eval-input footgun / general
    },
    "c": {
        "gets": "high", "strcpy": "high", "strcat": "high",
        "sprintf": "high", "vsprintf": "high", "scanf": "high",
        "system": "high", "popen": "high", "exec": "high",
        "execl": "high", "execlp": "high", "execv": "high", "execvp": "high",
        "strncpy": "medium", "strncat": "medium", "memcpy": "medium",
        "memmove": "medium", "sscanf": "medium", "alloca": "medium",
        "tmpnam": "medium", "mktemp": "medium", "rand": "medium",
    },
    "java": {
        "exec": "high",            # Runtime.exec
        "readObject": "high",      # unsafe deserialization
        "eval": "high",            # ScriptEngine.eval
    },
    "csharp": {
        "Eval": "high",
        "Deserialize": "medium",
    },
    "bash": {
        "eval": "high", "dd": "high", "mkfs": "high",
        "nc": "high", "ncat": "high", "netcat": "high",
        "curl": "medium", "wget": "medium",
        "rm": "medium", "chmod": "medium", "chown": "medium",
        "sudo": "medium", "ssh": "medium", "scp": "medium",
        "iptables": "medium",
    },
}
# C++ shares C's unsafe surface.
DANGEROUS["cpp"] = dict(DANGEROUS["c"])


def sast_severity(lang, *names):
    """Return 'high'/'medium' if any supplied name is a known-dangerous call
    for the language, else None. Checks bare name and dotted path."""
    cat = DANGEROUS.get(lang, {})
    if not cat:
        return None
    hit = None
    for n in names:
        if n in cat:
            sev = cat[n]
            if sev == "high":
                return "high"
            hit = hit or sev
    return hit


# CWE (Common Weakness Enumeration) tags for the flagged calls.  Attaching a
# recognised weakness id makes findings credible and maps neatly onto OWASP /
# secure-coding rubrics in a report.
CWE = {
    # command / code execution
    "system": "CWE-78 OS Command Injection",
    "popen": "CWE-78 OS Command Injection",
    "os.system": "CWE-78 OS Command Injection",
    "os.popen": "CWE-78 OS Command Injection",
    "subprocess.Popen": "CWE-78 OS Command Injection",
    "subprocess.call": "CWE-78 OS Command Injection",
    "subprocess.run": "CWE-78 OS Command Injection",
    "subprocess.check_output": "CWE-78 OS Command Injection",
    "exec": "CWE-95 Code Injection (eval)",
    "execl": "CWE-78 OS Command Injection",
    "execlp": "CWE-78 OS Command Injection",
    "execv": "CWE-78 OS Command Injection",
    "execvp": "CWE-78 OS Command Injection",
    "eval": "CWE-95 Code Injection (eval)",
    "compile": "CWE-95 Code Injection (eval)",
    "__import__": "CWE-95 Code Injection (eval)",
    # memory safety (C/C++)
    "gets": "CWE-242 Dangerous Function / CWE-120 Buffer Overflow",
    "strcpy": "CWE-120 Buffer Copy without Size Check",
    "strcat": "CWE-120 Buffer Copy without Size Check",
    "sprintf": "CWE-120 Buffer Copy without Size Check",
    "vsprintf": "CWE-120 Buffer Copy without Size Check",
    "scanf": "CWE-120 Buffer Copy without Size Check",
    "strncpy": "CWE-120 Possible Off-by-one / Truncation",
    "strncat": "CWE-120 Possible Off-by-one / Truncation",
    "memcpy": "CWE-787 Out-of-bounds Write",
    "memmove": "CWE-787 Out-of-bounds Write",
    "sscanf": "CWE-120 Buffer Copy without Size Check",
    "alloca": "CWE-770 Uncontrolled Stack Allocation",
    "tmpnam": "CWE-377 Insecure Temporary File",
    "mktemp": "CWE-377 Insecure Temporary File",
    "rand": "CWE-330 Weak Randomness",
    # deserialization
    "pickle.load": "CWE-502 Deserialization of Untrusted Data",
    "pickle.loads": "CWE-502 Deserialization of Untrusted Data",
    "marshal.loads": "CWE-502 Deserialization of Untrusted Data",
    "yaml.load": "CWE-502 Deserialization of Untrusted Data",
    "readObject": "CWE-502 Deserialization of Untrusted Data",
    "Deserialize": "CWE-502 Deserialization of Untrusted Data",
    "input": "CWE-20 Improper Input Validation",
    # shell
    "dd": "CWE-77 Destructive Command",
    "mkfs": "CWE-77 Destructive Command",
    "rm": "CWE-77 Destructive Command",
    "nc": "CWE-506 Suspicious Network Tool",
    "ncat": "CWE-506 Suspicious Network Tool",
    "netcat": "CWE-506 Suspicious Network Tool",
    "curl": "CWE-494 Download of Code Without Integrity Check",
    "wget": "CWE-494 Download of Code Without Integrity Check",
    "chmod": "CWE-732 Incorrect Permission Assignment",
    "chown": "CWE-732 Incorrect Permission Assignment",
    "sudo": "CWE-250 Execution with Unnecessary Privileges",
}


def cwe_for(name):
    return CWE.get(name)


# ----------------------------------------------------------------------------
#  Hardcoded-secret detection.  Regex patterns for the most common credential
#  shapes.  Like the SAST layer this is a fast first pass, not a guarantee.
#  Each pattern is (label, compiled_regex).
# ----------------------------------------------------------------------------
import re as _re
SECRET_PATTERNS = [
    ("AWS Access Key",     _re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key",     _re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("GitHub Token",       _re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("Slack Token",        _re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API Key",     _re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Private Key Block",  _re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT",                _re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Generic Credential", _re.compile(
        r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)"
        r"\s*[:=]\s*['\"][^'\"\s]{6,}['\"]")),
]


def scan_secrets(code):
    """Return a list of (label, line_number, snippet) for likely secrets."""
    findings = []
    for i, line in enumerate(code.splitlines(), 1):
        if len(line) > 500:                 # skip minified / data blobs
            continue
        for label, rx in SECRET_PATTERNS:
            if rx.search(line):
                snippet = line.strip()[:60]
                findings.append((label, i, snippet))
                break                        # one hit per line is enough
    return findings


# ----------------------------------------------------------------------------
#  Cyclomatic complexity (McCabe).  complexity = 1 + number of decision points.
#  Exact for Python (via the AST); an approximation for the tree-sitter
#  languages (counts control-flow branch nodes; boolean short-circuits are not
#  counted there, so the number is a slight under-estimate but still a useful
#  relative signal for spotting the gnarliest functions).
# ----------------------------------------------------------------------------
_TS_DECISION = {
    "if_statement", "elif_clause", "else_if_clause",
    "for_statement", "for_range_loop", "while_statement", "do_statement",
    "enhanced_for_statement", "foreach_statement", "for_in_statement",
    "case_statement", "switch_section", "when_entry", "case_item",
    "catch_clause", "except_clause",
    "conditional_expression", "ternary_expression",
}


def _ts_complexity(node):
    if node is None:
        return 1
    count = 1
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in _TS_DECISION:
            count += 1
        stack.extend(n.children)
    return count


def _py_complexity(fn):
    """McCabe complexity of a Python function, not descending into nested
    def/class scopes (those are measured as their own nodes)."""
    count = 1
    stack = list(ast.iter_child_nodes(fn))
    match_case = getattr(ast, "match_case", None)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue                         # separate scope
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While,
                          ast.ExceptHandler, ast.IfExp, ast.Assert)):
            count += 1
        elif isinstance(n, ast.BoolOp):
            count += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            count += 1 + len(n.ifs)
        elif match_case is not None and isinstance(n, match_case):
            count += 1
        stack.extend(ast.iter_child_nodes(n))
    return count


# ============================================================================
#  SchemaGraph -- a thin, typed wrapper around a directed graph
# ============================================================================

class SchemaGraph:
    """Holds the nodes and relations that make up a neural schema."""

    def __init__(self, title="schema", kind="code", language=None, source=None):
        self.title = title
        self.kind = kind                # "code" | "system"
        self.language = language
        self.source = source
        self.g = nx.DiGraph() if nx is not None else None
        # fallback storage if networkx is unavailable
        self._nodes = {}                # id -> attrs
        self._edges = []                # (src, dst, relation)

    # -- construction -------------------------------------------------------
    def add_node(self, node_id, kind, label, **meta):
        attrs = {"kind": kind, "label": str(label), **meta}
        if node_id not in self._nodes:
            self._nodes[node_id] = attrs
            if self.g is not None:
                self.g.add_node(node_id, **attrs)
        return node_id

    def add_edge(self, src, dst, relation):
        # self-edges are allowed here (they capture direct recursion); the
        # containment builders already avoid parent==child at the source, and
        # the renderer skips zero-length self segments.
        if src is None or dst is None:
            return
        self._edges.append((src, dst, relation))
        if self.g is not None:
            self.g.add_edge(src, dst, relation=relation)

    def has_node(self, node_id):
        return node_id in self._nodes

    # -- inspection ---------------------------------------------------------
    def nodes(self):
        return self._nodes

    def edges(self):
        return self._edges

    def neighbors(self, node_id):
        out = set()
        for s, d, _ in self._edges:
            if s == node_id:
                out.add(d)
            elif d == node_id:
                out.add(s)
        return out

    def degree(self):
        deg = defaultdict(int)
        for s, d, _ in self._edges:
            deg[s] += 1
            deg[d] += 1
        return deg

    def counts(self):
        c = defaultdict(int)
        for a in self._nodes.values():
            c[a["kind"]] += 1
        return dict(c)

    # -- serialisation ------------------------------------------------------
    def to_dict(self):
        return {
            "meta": {
                "title": self.title,
                "kind": self.kind,
                "language": self.language,
                "source": self.source,
                "generated": datetime.datetime.now().isoformat(timespec="seconds"),
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "counts_by_kind": self.counts(),
            },
            "nodes": [{"id": nid, **attrs} for nid, attrs in self._nodes.items()],
            "edges": [{"source": s, "target": d, "relation": r}
                      for (s, d, r) in self._edges],
        }


# ============================================================================
#  tree-sitter helpers
# ============================================================================

def _ts_captures(language, root, query_str):
    """Run a tree-sitter query, returning {capture_name: [nodes]}.

    Compatible with tree-sitter 0.25/0.26 (Query + QueryCursor). Any grammar
    mismatch degrades gracefully to an empty result instead of raising.
    """
    try:
        cur = ts.QueryCursor(ts.Query(language, query_str))
        return cur.captures(root)
    except Exception:
        return {}


def _txt(node):
    return node.text.decode("utf-8", errors="replace")


def _span(node):
    return (node.start_byte, node.end_byte)


def _line(node):
    return node.start_point[0] + 1


def _cpp_function_name(fn_node):
    """Find the display name of a C/C++ function_definition node.

    Handles free functions, class methods (field_identifier), qualified names
    (A::B::f), destructors and operators, plus pointer-returning functions.
    """
    stack = [fn_node]
    while stack:
        n = stack.pop()
        if n.type == "function_declarator":
            d = n.child_by_field_name("declarator")
            if d is None:
                continue
            if d.type in ("identifier", "field_identifier", "qualified_identifier",
                          "destructor_name", "operator_name"):
                return _txt(d)
            # nested (e.g. parenthesized) -> search for first identifier
            sub = [d]
            while sub:
                s = sub.pop()
                if s.type in ("identifier", "field_identifier"):
                    return _txt(s)
                sub.extend(s.children)
            return _txt(d)
        stack.extend(n.children)
    return None


def _include_path(inc_node):
    """Extract just the header path from a `#include <x>` / `"x"` node."""
    raw = _txt(inc_node).strip()
    if raw.startswith("#include"):
        raw = raw[len("#include"):].strip()
    return raw.strip().strip("<>").strip('"').strip()


# ============================================================================
#  TreeSitterAnalyzer -- C / C++ / Java / C# / Bash
# ============================================================================

class TreeSitterAnalyzer:
    """Extracts an architecture schema from a source file via tree-sitter."""

    def __init__(self, include_external=True, external_cap=80, sast=True):
        self.include_external = include_external
        self.external_cap = external_cap
        self.sast = sast
        self.lang = None

    # -- public entry -------------------------------------------------------
    def analyze(self, path, lang, code=None):
        if not _TS_OK:
            raise RuntimeError("tree-sitter is not installed.")
        self.lang = lang
        if code is None:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        data = code.encode("utf-8", errors="replace")
        language = get_language(lang)
        parser = get_parser(lang)
        root = parser.parse(data).root_node

        sg = SchemaGraph(title=os.path.basename(path), kind="code",
                         language=lang, source=path)
        module_id = f"module:{path}"
        sg.add_node(module_id, K_MODULE, os.path.basename(path), path=path,
                    language=lang, lines=code.count("\n") + 1)

        if lang in ("c", "cpp"):
            self._c_family(sg, module_id, language, root, lang)
        elif lang == "java":
            self._java(sg, module_id, language, root)
        elif lang == "csharp":
            self._csharp(sg, module_id, language, root)
        elif lang == "bash":
            self._bash(sg, module_id, language, root)
        else:
            raise ValueError(f"Unsupported tree-sitter language: {lang}")
        return sg

    # -- generic containment / call resolution -----------------------------
    def _finalise(self, sg, module_id, entities, calls, bases,
                  external_rel=R_CALLS):
        """Wire up containment, method/function reclassification, inheritance
        and the call graph, given raw positional captures.

        entities : list of dicts {id, kind, name, span, line}
        calls    : list of dicts {name, span}     (call sites)
        bases    : list of dicts {name, span, relation}
        """
        # 1) containment by smallest enclosing span
        ordered = sorted(entities, key=lambda e: e["span"][1] - e["span"][0])

        def enclosing(byte_pos, kinds=None, exclude_id=None):
            best = None
            best_size = None
            for e in ordered:
                if exclude_id is not None and e["id"] == exclude_id:
                    continue
                if kinds is not None and e["kind"] not in kinds:
                    continue
                s, en = e["span"]
                if s <= byte_pos < en:
                    size = en - s
                    if best_size is None or size < best_size:
                        best, best_size = e, size
            return best

        container_kinds = {K_NAMESPACE, K_CLASS, K_STRUCT, K_INTERFACE,
                           K_FUNCTION, K_METHOD}
        for e in entities:
            parent = enclosing(e["span"][0], kinds=container_kinds,
                               exclude_id=e["id"])
            # reclassify a function whose parent is a type -> method
            if e["kind"] == K_FUNCTION and parent is not None and \
                    parent["kind"] in (K_CLASS, K_STRUCT, K_INTERFACE):
                e["kind"] = K_METHOD
                sg._nodes[e["id"]]["kind"] = K_METHOD
                if sg.g is not None:
                    sg.g.nodes[e["id"]]["kind"] = K_METHOD
            sg.add_edge(parent["id"] if parent else module_id, e["id"], R_CONTAINS)

        # 2) inheritance / implementation
        type_by_name = {e["name"]: e for e in entities
                        if e["kind"] in (K_CLASS, K_STRUCT, K_INTERFACE)}
        for b in bases:
            owner = enclosing(b["span"][0],
                              kinds={K_CLASS, K_STRUCT, K_INTERFACE})
            if owner is None:
                continue
            target = type_by_name.get(b["name"])
            if target is not None:
                tid = target["id"]
            else:
                tid = f"external:{b['name']}"
                sg.add_node(tid, K_EXTERNAL, b["name"], external=True)
            sg.add_edge(owner["id"], tid, b["relation"])

        # 3) call graph  (with optional SAST tagging)
        callable_by_name = {}
        for e in entities:
            if e["kind"] in (K_FUNCTION, K_METHOD):
                callable_by_name.setdefault(e["name"], e)
        ext_added = 0
        for c in calls:
            caller = enclosing(c["span"][0], kinds={K_FUNCTION, K_METHOD})
            caller_id = caller["id"] if caller else module_id
            callee = callable_by_name.get(c["name"])
            if callee is not None:
                # resolves to a function this file defines -> not a vuln
                sg.add_edge(caller_id, callee["id"], R_CALLS)
                continue
            sev = sast_severity(self.lang, c["name"]) if self.sast else None
            if sev is not None:
                vid = f"vuln:{c['name']}:{c['span'][0]}"
                sg.add_node(vid, K_VULN, c["name"], severity=sev,
                            line=c.get("line"), call=c["name"],
                            cwe=cwe_for(c["name"]))
                sg.add_edge(caller_id, vid, R_DANGER)
            elif self.include_external:
                eid = f"external:{c['name']}"
                if not sg.has_node(eid):
                    if ext_added >= self.external_cap:
                        continue
                    ext_added += 1
                    sg.add_node(eid, K_EXTERNAL, c["name"], external=True)
                sg.add_edge(caller_id, eid, external_rel)

    # -- C / C++ ------------------------------------------------------------
    def _c_family(self, sg, module_id, language, root, lang):
        entities, calls, bases = [], [], []

        # includes
        for inc in _ts_captures(language, root, "(preproc_include) @i").get("i", []):
            path = _include_path(inc)
            if not path:
                continue
            iid = f"import:{path}"
            sg.add_node(iid, K_IMPORT, path, external=True)
            sg.add_edge(module_id, iid, R_INCLUDES)

        # namespaces (C++)
        if lang == "cpp":
            for ns in _ts_captures(
                    language, root,
                    "(namespace_definition name: (namespace_identifier) @n)"
            ).get("n", []):
                nid = f"ns:{_txt(ns)}:{ns.start_byte}"
                sg.add_node(nid, K_NAMESPACE, _txt(ns), line=_line(ns))
                entities.append({"id": nid, "kind": K_NAMESPACE, "name": _txt(ns),
                                 "span": _span(ns.parent), "line": _line(ns)})

        # classes / structs -- require a body so forward-decls and bare
        # references (e.g. `struct Point p;`) are not counted as definitions.
        class_q = ("(class_specifier name: (type_identifier) @c "
                   "body: (field_declaration_list))") if lang == "cpp" else ""
        if class_q:
            for cn in _ts_captures(language, root, class_q).get("c", []):
                cid = f"class:{_txt(cn)}:{cn.start_byte}"
                sg.add_node(cid, K_CLASS, _txt(cn), line=_line(cn))
                entities.append({"id": cid, "kind": K_CLASS, "name": _txt(cn),
                                 "span": _span(cn.parent), "line": _line(cn)})
        for sn in _ts_captures(
                language, root,
                "(struct_specifier name: (type_identifier) @s "
                "body: (field_declaration_list))"
        ).get("s", []):
            sid = f"struct:{_txt(sn)}:{sn.start_byte}"
            sg.add_node(sid, K_STRUCT, _txt(sn), line=_line(sn))
            entities.append({"id": sid, "kind": K_STRUCT, "name": _txt(sn),
                             "span": _span(sn.parent), "line": _line(sn)})

        # base classes (C++)
        if lang == "cpp":
            for cap in ("(base_class_clause (type_identifier) @b)",
                        "(base_class_clause (qualified_identifier) @b)"):
                for bn in _ts_captures(language, root, cap).get("b", []):
                    bases.append({"name": _txt(bn), "span": _span(bn),
                                  "relation": R_INHERITS})

        # functions / methods (name resolved by descent)
        for fn in _ts_captures(language, root, "(function_definition) @f").get("f", []):
            name = _cpp_function_name(fn)
            if not name:
                continue
            fid = f"func:{name}:{fn.start_byte}"
            sg.add_node(fid, K_FUNCTION, name, line=_line(fn),
                        complexity=_ts_complexity(fn))
            entities.append({"id": fid, "kind": K_FUNCTION, "name": name,
                             "span": _span(fn), "line": _line(fn)})

        # call sites
        for cap in ("(call_expression function: (identifier) @n)",
                    "(call_expression function: (field_expression field: (field_identifier) @n))",
                    "(call_expression function: (qualified_identifier) @n)"):
            for cn in _ts_captures(language, root, cap).get("n", []):
                nm = _txt(cn)
                if "::" in nm:
                    nm = nm.split("::")[-1]
                calls.append({"name": nm, "span": _span(cn), "line": _line(cn)})

        self._finalise(sg, module_id, entities, calls, bases)

    # -- Java ---------------------------------------------------------------
    def _java(self, sg, module_id, language, root):
        entities, calls, bases = [], [], []

        # package -> namespace
        for cap in ("(package_declaration (scoped_identifier) @p)",
                    "(package_declaration (identifier) @p)"):
            for pn in _ts_captures(language, root, cap).get("p", []):
                pid = f"ns:{_txt(pn)}"
                sg.add_node(pid, K_NAMESPACE, _txt(pn), line=_line(pn))
                sg.add_edge(module_id, pid, R_CONTAINS)

        # imports
        for cap in ("(import_declaration (scoped_identifier) @i)",
                    "(import_declaration (identifier) @i)"):
            for imp in _ts_captures(language, root, cap).get("i", []):
                iid = f"import:{_txt(imp)}"
                sg.add_node(iid, K_IMPORT, _txt(imp), external=True)
                sg.add_edge(module_id, iid, R_IMPORTS)

        # classes / interfaces / enums / records
        for q, kind in (
            ("(class_declaration name: (identifier) @n)", K_CLASS),
            ("(interface_declaration name: (identifier) @n)", K_INTERFACE),
            ("(enum_declaration name: (identifier) @n)", K_CLASS),
            ("(record_declaration name: (identifier) @n)", K_CLASS),
        ):
            for cn in _ts_captures(language, root, q).get("n", []):
                cid = f"type:{_txt(cn)}:{cn.start_byte}"
                sg.add_node(cid, kind, _txt(cn), line=_line(cn))
                entities.append({"id": cid, "kind": kind, "name": _txt(cn),
                                 "span": _span(cn.parent), "line": _line(cn)})

        # extends / implements
        for sup in _ts_captures(
                language, root, "(superclass (type_identifier) @s)").get("s", []):
            bases.append({"name": _txt(sup), "span": _span(sup),
                          "relation": R_INHERITS})
        for iface in _ts_captures(
                language, root,
                "(super_interfaces (type_list (type_identifier) @i))").get("i", []):
            bases.append({"name": _txt(iface), "span": _span(iface),
                          "relation": R_IMPLEMENTS})

        # methods + constructors
        for q in ("(method_declaration name: (identifier) @m)",
                  "(constructor_declaration name: (identifier) @m)"):
            for mn in _ts_captures(language, root, q).get("m", []):
                mid = f"func:{_txt(mn)}:{mn.start_byte}"
                sg.add_node(mid, K_FUNCTION, _txt(mn), line=_line(mn),
                            complexity=_ts_complexity(mn.parent))
                entities.append({"id": mid, "kind": K_FUNCTION, "name": _txt(mn),
                                 "span": _span(mn.parent), "line": _line(mn)})

        # invocations
        for inv in _ts_captures(
                language, root,
                "(method_invocation name: (identifier) @c)").get("c", []):
            calls.append({"name": _txt(inv), "span": _span(inv), "line": _line(inv)})

        self._finalise(sg, module_id, entities, calls, bases)

    # -- C# -----------------------------------------------------------------
    def _csharp(self, sg, module_id, language, root):
        entities, calls, bases = [], [], []

        for cap in ("(using_directive (identifier) @u)",
                    "(using_directive (qualified_name) @u)"):
            for un in _ts_captures(language, root, cap).get("u", []):
                uid = f"import:{_txt(un)}"
                sg.add_node(uid, K_IMPORT, _txt(un), external=True)
                sg.add_edge(module_id, uid, R_IMPORTS)

        for cap in ("(namespace_declaration name: (identifier) @n)",
                    "(namespace_declaration name: (qualified_name) @n)",
                    "(file_scoped_namespace_declaration name: (identifier) @n)",
                    "(file_scoped_namespace_declaration name: (qualified_name) @n)"):
            for nn in _ts_captures(language, root, cap).get("n", []):
                nid = f"ns:{_txt(nn)}:{nn.start_byte}"
                sg.add_node(nid, K_NAMESPACE, _txt(nn), line=_line(nn))
                entities.append({"id": nid, "kind": K_NAMESPACE, "name": _txt(nn),
                                 "span": _span(nn.parent), "line": _line(nn)})

        for q, kind in (
            ("(class_declaration name: (identifier) @n)", K_CLASS),
            ("(struct_declaration name: (identifier) @n)", K_STRUCT),
            ("(interface_declaration name: (identifier) @n)", K_INTERFACE),
            ("(record_declaration name: (identifier) @n)", K_CLASS),
            ("(enum_declaration name: (identifier) @n)", K_CLASS),
        ):
            for cn in _ts_captures(language, root, q).get("n", []):
                cid = f"type:{_txt(cn)}:{cn.start_byte}"
                sg.add_node(cid, kind, _txt(cn), line=_line(cn))
                entities.append({"id": cid, "kind": kind, "name": _txt(cn),
                                 "span": _span(cn.parent), "line": _line(cn)})

        for cap in ("(base_list (identifier) @b)",
                    "(base_list (qualified_name) @b)",
                    "(base_list (generic_name (identifier) @b))"):
            for bn in _ts_captures(language, root, cap).get("b", []):
                bases.append({"name": _txt(bn), "span": _span(bn),
                              "relation": R_INHERITS})

        for q in ("(method_declaration name: (identifier) @m)",
                  "(constructor_declaration name: (identifier) @m)",
                  "(local_function_statement name: (identifier) @m)"):
            for mn in _ts_captures(language, root, q).get("m", []):
                mid = f"func:{_txt(mn)}:{mn.start_byte}"
                sg.add_node(mid, K_FUNCTION, _txt(mn), line=_line(mn),
                            complexity=_ts_complexity(mn.parent))
                entities.append({"id": mid, "kind": K_FUNCTION, "name": _txt(mn),
                                 "span": _span(mn.parent), "line": _line(mn)})

        for cap in ("(invocation_expression function: (identifier) @c)",
                    "(invocation_expression function: (member_access_expression name: (identifier) @c))"):
            for cn in _ts_captures(language, root, cap).get("c", []):
                calls.append({"name": _txt(cn), "span": _span(cn), "line": _line(cn)})

        self._finalise(sg, module_id, entities, calls, bases)

    # -- Bash / sh ----------------------------------------------------------
    def _bash(self, sg, module_id, language, root):
        entities, calls = [], []

        # function definitions
        func_names = set()
        for fn in _ts_captures(
                language, root, "(function_definition name: (word) @f)").get("f", []):
            name = _txt(fn)
            func_names.add(name)
            fid = f"func:{name}:{fn.start_byte}"
            sg.add_node(fid, K_FUNCTION, name, line=_line(fn),
                        complexity=_ts_complexity(fn.parent))
            entities.append({"id": fid, "kind": K_FUNCTION, "name": name,
                             "span": _span(fn.parent), "line": _line(fn)})

        # variable assignments
        for vn in _ts_captures(
                language, root,
                "(variable_assignment name: (variable_name) @v)").get("v", []):
            vid = f"var:{_txt(vn)}"
            if not sg.has_node(vid):
                sg.add_node(vid, K_VARIABLE, _txt(vn), line=_line(vn))
                sg.add_edge(module_id, vid, R_CONTAINS)

        # commands: separate sourced files, internal function calls, external progs
        ext_added = 0
        for cmd in _ts_captures(language, root, "(command) @c").get("c", []):
            name_node = cmd.child_by_field_name("name")
            if name_node is None:
                continue
            name = _txt(name_node)
            span = _span(name_node)
            if name in ("source", "."):
                # first argument is the sourced file
                arg = None
                for ch in cmd.children:
                    if ch is name_node:
                        continue
                    if ch.type in ("word", "string", "concatenation", "raw_string"):
                        arg = _txt(ch).strip('"').strip("'")
                        break
                if arg:
                    sid = f"import:{arg}"
                    sg.add_node(sid, K_IMPORT, arg, external=True)
                    sg.add_edge(module_id, sid, R_SOURCES)
                continue
            line = _line(name_node)
            if name in func_names:
                calls.append({"name": name, "span": span, "line": line})
                continue
            sev = sast_severity("bash", name) if self.sast else None
            if sev is not None:
                vid = f"vuln:{name}:{span[0]}"
                sg.add_node(vid, K_VULN, name, severity=sev, line=line,
                            call=name, cwe=cwe_for(name))
                calls.append({"name": name, "span": span, "line": line,
                              "_vuln": vid})
            elif self.include_external:
                eid = f"external:{name}"
                if not sg.has_node(eid):
                    if ext_added >= self.external_cap:
                        continue
                    ext_added += 1
                    sg.add_node(eid, K_EXTERNAL, name, external=True, program=True)
                # attribute to enclosing function if any, else module
                calls.append({"name": name, "span": span, "line": line,
                              "_ext": eid})

        # resolve bash calls (internal + external) with a light finaliser
        ordered = sorted(entities, key=lambda e: e["span"][1] - e["span"][0])

        def enclosing(byte_pos):
            best, best_size = None, None
            for e in ordered:
                s, en = e["span"]
                if s <= byte_pos < en:
                    size = en - s
                    if best_size is None or size < best_size:
                        best, best_size = e, size
            return best

        # containment: nested functions -> parent function, else module
        for e in entities:
            parent = enclosing(e["span"][0])
            if parent and parent["id"] != e["id"]:
                sg.add_edge(parent["id"], e["id"], R_CONTAINS)
            else:
                sg.add_edge(module_id, e["id"], R_CONTAINS)

        by_name = {e["name"]: e for e in entities}
        for c in calls:
            caller = enclosing(c["span"][0])
            caller_id = caller["id"] if caller else module_id
            if "_vuln" in c:
                sg.add_edge(caller_id, c["_vuln"], R_DANGER)
            elif "_ext" in c:
                sg.add_edge(caller_id, c["_ext"], R_RUNS)
            else:
                tgt = by_name.get(c["name"])
                if tgt:
                    sg.add_edge(caller_id, tgt["id"], R_CALLS)


# ============================================================================
#  PythonAnalyzer -- rich extraction via the built-in `ast`
# ============================================================================

class PythonAnalyzer:
    def __init__(self, include_external=True, external_cap=80, sast=True):
        self.include_external = include_external
        self.external_cap = external_cap
        self.sast = sast

    def analyze(self, path, code=None):
        if code is None:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
        sg = SchemaGraph(title=os.path.basename(path), kind="code",
                         language="python", source=path)
        module_id = f"module:{path}"
        sg.add_node(module_id, K_MODULE, os.path.basename(path), path=path,
                    language="python", lines=code.count("\n") + 1)
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            sg.add_node("error", K_EXTERNAL, f"SyntaxError: {e.msg} (line {e.lineno})")
            sg.add_edge(module_id, "error", R_CONTAINS)
            return sg

        # collect callable ids by name for call resolution
        self.callables = {}     # name -> node_id
        self.classes = {}       # name -> node_id
        self.calls = []         # (caller_id, bare_name, dotted_name, lineno)
        self.ext_added = 0

        self._walk_body(sg, tree.body, parent_id=module_id, class_scope=False)

        # resolve calls
        cat = DANGEROUS.get("python", {})
        for caller_id, bare, dotted, is_attr, lineno in self.calls:
            local = self.callables.get(bare) or self.classes.get(bare)
            # --- SAST decision ---
            sev, label = None, None
            if self.sast:
                if is_attr:
                    # attribute call x.foo(): the qualified name is authoritative,
                    # so a local `def foo` does NOT shadow e.g. os.system(...)
                    if dotted in cat:
                        sev, label = cat[dotted], dotted
                    elif bare in cat:
                        sev, label = cat[bare], bare
                else:
                    # plain name call foo(): a local `def foo` shadows the builtin
                    if local is None and bare in cat:
                        sev, label = cat[bare], bare
            if sev is not None:
                vid = f"vuln:{label}:{lineno}"
                sg.add_node(vid, K_VULN, label, severity=sev, line=lineno,
                            call=label, cwe=cwe_for(label))
                sg.add_edge(caller_id, vid, R_DANGER)
                continue
            # --- call graph ---
            if local is not None:
                sg.add_edge(caller_id, local, R_CALLS)
            elif self.include_external and self.ext_added < self.external_cap:
                eid = f"external:{bare}"
                if not sg.has_node(eid):
                    sg.add_node(eid, K_EXTERNAL, bare, external=True)
                    self.ext_added += 1
                sg.add_edge(caller_id, eid, R_CALLS)
        return sg

    def _walk_body(self, sg, body, parent_id, class_scope, enclosing_fn=None):
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._handle_import(sg, node, parent_id)
            elif isinstance(node, ast.ClassDef):
                cid = f"class:{node.name}:{node.lineno}"
                sg.add_node(cid, K_CLASS, node.name, line=node.lineno)
                self.classes.setdefault(node.name, cid)
                sg.add_edge(parent_id, cid, R_CONTAINS)
                # bases
                for base in node.bases:
                    bname = self._name_of(base)
                    if not bname:
                        continue
                    if bname in self.classes:
                        bid = self.classes[bname]
                    else:
                        bid = f"external:{bname}"
                        sg.add_node(bid, K_EXTERNAL, bname, external=True)
                    sg.add_edge(cid, bid, R_INHERITS)
                self._walk_body(sg, node.body, cid, class_scope=True)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                kind = K_METHOD if class_scope else K_FUNCTION
                fid = f"func:{node.name}:{node.lineno}"
                nargs = len(node.args.args) + len(node.args.kwonlyargs)
                sg.add_node(fid, kind, node.name, line=node.lineno, params=nargs,
                            complexity=_py_complexity(node))
                self.callables.setdefault(node.name, fid)
                sg.add_edge(parent_id, fid, R_CONTAINS)
                # descend: capture calls made *inside* this function
                self._collect_calls(sg, node, fid)
                self._walk_body(sg, node.body, fid, class_scope=False,
                                enclosing_fn=fid)
            # (module/class-level plain statements are ignored to reduce noise)

    def _collect_calls(self, sg, fn_node, caller_id):
        # only walk THIS function's own body, not nested def bodies (those get
        # their own caller_id when _walk_body recurses into them)
        for sub in ast.walk(fn_node):
            if isinstance(sub, ast.Call):
                bare, dotted, is_attr = self._call_names(sub.func)
                if bare:
                    self.calls.append((caller_id, bare, dotted, is_attr,
                                       getattr(sub, "lineno", None)))

    @staticmethod
    def _call_names(func):
        """Return (bare_name, dotted_path, is_attribute_call) for a call target.
        e.g. os.system -> ('system', 'os.system', True);
             eval       -> ('eval', 'eval', False)."""
        if isinstance(func, ast.Name):
            return func.id, func.id, False
        if isinstance(func, ast.Attribute):
            parts = []
            cur = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            parts.reverse()
            return func.attr, ".".join(parts), True
        return None, None, False

    def _handle_import(self, sg, node, parent_id):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                iid = f"import:{name}"
                sg.add_node(iid, K_IMPORT, name, external=True)
                sg.add_edge(parent_id, iid, R_IMPORTS)
        else:  # ImportFrom
            mod = ("." * (node.level or 0)) + (node.module or "")
            for alias in node.names:
                label = f"{mod}.{alias.name}" if mod else alias.name
                iid = f"import:{label}"
                sg.add_node(iid, K_IMPORT, label, external=True)
                sg.add_edge(parent_id, iid, R_IMPORTS)

    @staticmethod
    def _name_of(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


# ============================================================================
#  Path dispatcher -- single file or whole project directory
# ============================================================================

def _resolve_lang(path):
    ext = os.path.splitext(path)[1].lower()
    lang = EXT_LANG.get(ext)
    if lang == "c_header":
        # sniff: treat as C++ if it looks C++-ish, else C
        try:
            head = open(path, "r", encoding="utf-8", errors="replace").read(4000)
        except Exception:
            head = ""
        cpp_markers = ("class ", "namespace ", "template", "std::", "public:",
                       "private:", "::")
        lang = "cpp" if any(m in head for m in cpp_markers) else "c"
    return lang


def _add_secret_nodes(sg, code):
    """Attach hardcoded-secret findings to the module node as vuln nodes."""
    module_id = next((nid for nid, a in sg.nodes().items()
                      if a["kind"] == K_MODULE), None)
    if module_id is None:
        return
    for label, line, snippet in scan_secrets(code):
        sid = f"secret:{label}:{line}"
        sg.add_node(sid, K_VULN, f"secret: {label}", severity="high", line=line,
                    secret=True, cwe="CWE-798 Hardcoded Credentials",
                    snippet=snippet)
        sg.add_edge(module_id, sid, R_DANGER)


def analyze_file(path, include_external=True, sast=True):
    lang = _resolve_lang(path)
    if lang is None:
        raise ValueError(f"Unsupported file type: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()
    if lang == "python":
        sg = PythonAnalyzer(include_external, sast=sast).analyze(path, code=code)
    else:
        sg = TreeSitterAnalyzer(include_external, sast=sast).analyze(
            path, lang, code=code)
    if sast:
        _add_secret_nodes(sg, code)
    return sg


def analyze_directory(path, include_external=True, sast=True, max_files=250,
                      progress=None):
    """Analyse every supported source file under a folder into one schema.

    progress : optional callable(done:int, total:int, current_path:str) invoked
               after each file -- used by the GUI to drive a progress display.
    """
    sg = SchemaGraph(title=os.path.basename(path.rstrip("/")) or path,
                     kind="code", language="mixed", source=path)
    proj_id = f"project:{path}"
    sg.add_node(proj_id, K_PROJECT, os.path.basename(path.rstrip("/")) or path,
                path=path)

    files = []
    for base, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for n in names:
            if os.path.splitext(n)[1].lower() in EXT_LANG:
                files.append(os.path.join(base, n))
    files.sort()
    files = files[:max_files]
    total = len(files)

    stem_to_module = {}     # for light python cross-file linking
    for i, fp in enumerate(files, 1):
        try:
            sub = analyze_file(fp, include_external, sast=sast)
        except Exception:
            eid = f"error:{fp}"
            sg.add_node(eid, K_EXTERNAL, f"{os.path.basename(fp)} (parse error)")
            sg.add_edge(proj_id, eid, R_CONTAINS)
            if progress:
                progress(i, total, fp)
            continue
        # merge sub-graph into the project graph
        module_id = None
        for nid, attrs in sub.nodes().items():
            sg._merge_node(nid, attrs)
            if attrs["kind"] == K_MODULE:
                module_id = nid
        for (s, d, r) in sub.edges():
            sg.add_edge(s, d, r)
        if module_id:
            sg.add_edge(proj_id, module_id, R_CONTAINS)
            stem = os.path.splitext(os.path.basename(fp))[0]
            stem_to_module[stem] = module_id
        if progress:
            progress(i, total, fp)

    # light cross-module import links (python-style, by module stem)
    for nid, attrs in list(sg.nodes().items()):
        if attrs["kind"] == K_IMPORT:
            top = attrs["label"].lstrip(".").split(".")[0]
            if top in stem_to_module and stem_to_module[top] != nid:
                sg.add_edge(nid, stem_to_module[top], R_IMPORTS)
    return sg


# helper used by analyze_directory to merge nodes without clobbering
def _merge_node(self, nid, attrs):
    if nid not in self._nodes:
        self._nodes[nid] = dict(attrs)
        if self.g is not None:
            self.g.add_node(nid, **attrs)
SchemaGraph._merge_node = _merge_node


# ============================================================================
#  SystemAnalyzer -- live OS introspection
# ============================================================================

class SystemAnalyzer:
    def __init__(self, top_processes=40, include_connections=False,
                 conns_per_proc=3):
        self.top_processes = top_processes
        self.include_connections = include_connections
        self.conns_per_proc = conns_per_proc

    def analyze(self):
        if psutil is None:
            raise RuntimeError("psutil is not installed.")
        host = socket.gethostname()
        sg = SchemaGraph(title=f"system: {host}", kind="system",
                         language=None, source=host)
        sys_id = "system:root"
        sg.add_node(sys_id, K_SYSTEM, host,
                    os=f"{platform.system()} {platform.release()}",
                    python=platform.python_version())

        self._resources(sg, sys_id)
        self._processes(sg, sys_id)
        return sg

    def _resources(self, sg, sys_id):
        # CPU
        try:
            logical = psutil.cpu_count() or 0
            phys = psutil.cpu_count(logical=False) or 0
            usage = psutil.cpu_percent(interval=0.1)
            sg.add_node("cpu", K_CPU,
                        f"CPU  {logical}c / {phys}p  ·  {usage:.0f}%",
                        logical=logical, physical=phys, usage_pct=usage)
            sg.add_edge(sys_id, "cpu", R_USES)
        except Exception:
            pass
        # Memory
        try:
            vm = psutil.virtual_memory()
            sg.add_node("memory", K_MEMORY,
                        f"RAM  {vm.used/1e9:.1f} / {vm.total/1e9:.1f} GB  ·  {vm.percent:.0f}%",
                        total_gb=round(vm.total/1e9, 2),
                        used_gb=round(vm.used/1e9, 2), pct=vm.percent)
            sg.add_edge(sys_id, "memory", R_USES)
        except Exception:
            pass
        # Disks
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    u = psutil.disk_usage(part.mountpoint)
                    label = f"{part.mountpoint}  {u.used/1e9:.0f}/{u.total/1e9:.0f}GB"
                    did = f"disk:{part.mountpoint}"
                    sg.add_node(did, K_DISK, label, device=part.device,
                                fstype=part.fstype, pct=u.percent)
                    sg.add_edge(sys_id, did, R_USES)
                except Exception:
                    continue
        except Exception:
            pass
        # Network interfaces
        try:
            net_id = "network"
            sg.add_node(net_id, K_NET, "Network")
            sg.add_edge(sys_id, net_id, R_CONTAINS)
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                ip = next((a.address for a in addr_list
                           if a.family == socket.AF_INET), None)
                up = stats[iface].isup if iface in stats else False
                label = f"{iface}" + (f"  {ip}" if ip else "") + ("  ↑" if up else "  ↓")
                iid = f"iface:{iface}"
                sg.add_node(iid, K_IFACE, label, ip=ip, is_up=up)
                sg.add_edge(net_id, iid, R_CONTAINS)
        except Exception:
            pass
        # Logged-in users
        try:
            seen = set()
            for u in psutil.users():
                if u.name in seen:
                    continue
                seen.add(u.name)
                uid = f"user:{u.name}"
                sg.add_node(uid, K_USER, u.name, terminal=getattr(u, "terminal", None))
                sg.add_edge(sys_id, uid, R_CONTAINS)
        except Exception:
            pass

    def _processes(self, sg, sys_id):
        procs = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "username",
                                      "memory_info", "cpu_percent"]):
            info = p.info
            rss = info["memory_info"].rss if info.get("memory_info") else 0
            procs[info["pid"]] = {
                "pid": info["pid"], "ppid": info.get("ppid"),
                "name": info.get("name") or "?",
                "user": info.get("username"), "rss": rss,
                "cpu": info.get("cpu_percent") or 0.0,
            }
        if not procs:
            return
        # pick the heaviest N by RSS
        top = sorted(procs.values(), key=lambda d: d["rss"], reverse=True)
        sel = {d["pid"] for d in top[:self.top_processes]}
        # add ancestors to keep the tree connected
        for pid in list(sel):
            cur, guard = pid, 0
            while guard < 64:
                guard += 1
                ppid = procs.get(cur, {}).get("ppid")
                if ppid is None or ppid == 0 or ppid not in procs or ppid in sel:
                    if ppid in procs:
                        sel.add(ppid)
                    break
                sel.add(ppid)
                cur = ppid

        for pid in sel:
            d = procs[pid]
            nid = f"proc:{pid}"
            privileged = d["user"] in ("root", "SYSTEM", "LocalSystem")
            crown = "  ⚑root" if privileged else ""
            label = f"{d['name']}  ({pid})  {d['rss']/1e6:.0f}MB{crown}"
            sg.add_node(nid, K_PROCESS, label, pid=pid, ppid=d["ppid"],
                        user=d["user"], rss_mb=round(d["rss"]/1e6, 1),
                        cpu_pct=d["cpu"], privileged=privileged)
        # parent edges
        for pid in sel:
            d = procs[pid]
            ppid = d["ppid"]
            if ppid in sel and ppid != pid:
                sg.add_edge(f"proc:{ppid}", f"proc:{pid}", R_PARENT)
            else:
                sg.add_edge(sys_id, f"proc:{pid}", R_CONTAINS)

        # optional per-process network introspection.
        #   LISTEN sockets  -> open_port nodes (potential exposure / backdoor)
        #   established conns -> connection nodes
        # (some of this may need sudo; without it, unreadable procs are skipped.)
        if self.include_connections:
            for pid in sel:
                try:
                    p = psutil.Process(pid)
                    conns = p.net_connections(kind="inet")
                except Exception:
                    try:
                        conns = psutil.Process(pid).connections(kind="inet")
                    except Exception:
                        continue
                added = 0
                for c in conns:
                    if added >= max(self.conns_per_proc, 4):
                        break
                    if c.status == "LISTEN" and c.laddr:
                        label = f":{c.laddr.port} LISTEN"
                        cid = f"port:{pid}:{c.laddr.ip}:{c.laddr.port}"
                        sg.add_node(cid, K_PORT, label, status="LISTEN",
                                    port=c.laddr.port, addr=c.laddr.ip, pid=pid)
                        sg.add_edge(f"proc:{pid}", cid, R_LISTENS)
                        added += 1
                    elif c.raddr:
                        label = f"{c.raddr.ip}:{c.raddr.port}"
                        cid = f"conn:{pid}:{label}:{added}"
                        sg.add_node(cid, K_CONN, label,
                                    status=getattr(c, "status", ""))
                        sg.add_edge(f"proc:{pid}", cid, R_CONNECTS)
                        added += 1


# ============================================================================
#  Layout + matplotlib drawing (shared by GUI and PNG export)
# ============================================================================

def compute_layout(sg, algo="spring", seed=42):
    import math
    if nx is None or sg.g is None:
        # trivial circular fallback
        n = len(sg._nodes)
        return {nid: (math.cos(2*math.pi*i/max(n, 1)),
                      math.sin(2*math.pi*i/max(n, 1)))
                for i, nid in enumerate(sg._nodes)}
    G = sg.g
    n = max(G.number_of_nodes(), 1)
    try:
        if algo == "kamada":
            return nx.kamada_kawai_layout(G)
        elif algo == "shell":
            return nx.shell_layout(G)
        elif algo == "circular":
            return nx.circular_layout(G)
        else:
            k = 1.6 / (n ** 0.5)
            return nx.spring_layout(G, k=k, iterations=120, seed=seed)
    except Exception:
        pass

    try:
        return nx.circular_layout(G)
    except Exception:
        n = len(sg._nodes)
        return {nid: (math.cos(2*math.pi*i/max(n, 1)),
                      math.sin(2*math.pi*i/max(n, 1)))
                for i, nid in enumerate(sg._nodes)}


# ============================================================================
#  Static-analysis report  (dead code, cycles, complexity, security)
# ============================================================================

_ENTRY_NAMES = {"main", "__init__", "__new__", "__call__", "__enter__",
                "__exit__", "setup", "teardown", "setUp", "tearDown",
                "wmain", "WinMain", "_start"}


def _cycles(digraph, cap=25):
    if nx is None:
        return []
    out = []
    try:
        import itertools
        for cyc in itertools.islice(nx.simple_cycles(digraph), cap):
            out.append(cyc)
    except Exception:
        pass
    return out


def build_report(sg):
    """Compute a static-analysis report from a code schema.
    Returns a plain dict so it can be printed, rendered or serialised."""
    nodes = sg.nodes()
    edges = sg.edges()

    # incoming call counts per node
    in_calls = defaultdict(int)
    for s, d, r in edges:
        if r == R_CALLS:
            in_calls[d] += 1

    functions = []
    for nid, a in nodes.items():
        if a["kind"] in (K_FUNCTION, K_METHOD):
            functions.append({
                "id": nid, "label": a["label"], "kind": a["kind"],
                "line": a.get("line"), "complexity": a.get("complexity", 1),
                "callers": in_calls.get(nid, 0),
            })

    comps = [f["complexity"] for f in functions] or [0]
    avg_c = round(sum(comps) / len(comps), 2) if functions else 0
    max_c = max(comps) if comps else 0
    hotspots = sorted([f for f in functions if f["complexity"] >= 8],
                      key=lambda f: -f["complexity"])[:15]

    # dead code: 0 static callers, excluding entry points / dunders / tests
    dead = []
    for f in functions:
        name = f["label"]
        if f["callers"] > 0:
            continue
        if name in _ENTRY_NAMES or name.startswith("__") or \
                name.startswith("test") or name.endswith("_test"):
            continue
        dead.append(f)
    dead.sort(key=lambda f: (f["kind"], f["label"]))

    # recursion / mutual recursion (cycles in the call graph)
    callg = nx.DiGraph() if nx is not None else None
    if callg is not None:
        for s, d, r in edges:
            if r == R_CALLS:
                callg.add_edge(s, d)
    recursion = []
    for cyc in _cycles(callg) if callg is not None else []:
        recursion.append([nodes[n]["label"] for n in cyc if n in nodes])

    # circular module dependencies (A -> import -> B  collapsed to A -> B)
    owner = {}
    for s, d, r in edges:
        if r in (R_IMPORTS, R_INCLUDES, R_SOURCES) and \
                nodes.get(s, {}).get("kind") == K_MODULE and \
                nodes.get(d, {}).get("kind") == K_IMPORT:
            owner[d] = s
    modg = nx.DiGraph() if nx is not None else None
    if modg is not None:
        for s, d, r in edges:
            if r == R_IMPORTS and nodes.get(s, {}).get("kind") == K_IMPORT and \
                    nodes.get(d, {}).get("kind") == K_MODULE and s in owner:
                if owner[s] != d:
                    modg.add_edge(owner[s], d)
    circular_modules = []
    for cyc in _cycles(modg) if modg is not None else []:
        circular_modules.append([nodes[n]["label"] for n in cyc if n in nodes])

    # security findings
    vulns, secrets = [], []
    for nid, a in nodes.items():
        if a["kind"] != K_VULN:
            continue
        item = {"label": a["label"], "severity": a.get("severity", "?"),
                "line": a.get("line"), "cwe": a.get("cwe")}
        if a.get("secret"):
            item["snippet"] = a.get("snippet")
            secrets.append(item)
        else:
            vulns.append(item)
    vulns.sort(key=lambda v: (v["severity"] != "high", v["label"]))
    secrets.sort(key=lambda v: (v["line"] or 0))

    ports = [a["label"] for a in nodes.values() if a["kind"] == K_PORT]
    roots = [a["label"] for a in nodes.values()
             if a["kind"] == K_PROCESS and a.get("privileged")]

    return {
        "title": sg.title, "language": sg.language, "kind": sg.kind,
        "node_count": len(nodes), "edge_count": len(edges),
        "counts": sg.counts(),
        "n_functions": len(functions),
        "avg_complexity": avg_c, "max_complexity": max_c,
        "hotspots": hotspots, "dead_code": dead,
        "recursion": recursion, "circular_modules": circular_modules,
        "vulns": vulns, "secrets": secrets,
        "ports": ports, "root_procs": roots,
    }


def report_to_text(rep):
    """Render a report dict as a readable console string."""
    L = []
    add = L.append
    add("=" * 66)
    add(f" STATIC ANALYSIS REPORT  ·  {rep['title']}  ({rep['language']})")
    add("=" * 66)
    add(f" nodes: {rep['node_count']}   edges: {rep['edge_count']}   "
        f"functions/methods: {rep['n_functions']}")
    add(f" complexity: avg {rep['avg_complexity']}, max {rep['max_complexity']}")

    if rep["hotspots"]:
        add("\n-- Complexity hotspots (McCabe >= 8) " + "-" * 27)
        for f in rep["hotspots"]:
            loc = f" (line {f['line']})" if f["line"] else ""
            add(f"   {f['complexity']:>3}  {f['label']}{loc}")

    if rep["dead_code"]:
        add("\n-- Possibly-unused (no static caller found) " + "-" * 20)
        add("   [heuristic: dynamic dispatch / framework hooks may call these]")
        for f in rep["dead_code"][:25]:
            loc = f" (line {f['line']})" if f["line"] else ""
            add(f"   {f['kind']:<8} {f['label']}{loc}")

    if rep["recursion"]:
        add("\n-- Recursion / call cycles " + "-" * 37)
        for cyc in rep["recursion"][:15]:
            add("   " + " -> ".join(cyc) + (" -> …" if len(cyc) > 1 else " (self)"))

    if rep["circular_modules"]:
        add("\n-- Circular module dependencies " + "-" * 32)
        for cyc in rep["circular_modules"]:
            add("   " + " -> ".join(cyc) + " -> …")

    if rep["vulns"]:
        hi = sum(1 for v in rep["vulns"] if v["severity"] == "high")
        add(f"\n-- SAST: {len(rep['vulns'])} dangerous call(s), {hi} high " + "-" * 20)
        for v in rep["vulns"]:
            loc = f" line {v['line']}" if v["line"] else ""
            cwe = f"  [{v['cwe']}]" if v["cwe"] else ""
            add(f"   {v['severity']:<6} {v['label']}{loc}{cwe}")

    if rep["secrets"]:
        add(f"\n-- Hardcoded secrets: {len(rep['secrets'])} " + "-" * 34)
        for s in rep["secrets"]:
            add(f"   line {s['line']}: {s['label']}  ({s.get('snippet','')})")

    if rep["ports"]:
        add(f"\n-- Listening ports: {', '.join(sorted(set(rep['ports']))[:20])}")
    if rep["root_procs"]:
        add(f"-- Root/SYSTEM processes: {len(rep['root_procs'])}")

    if not any((rep["hotspots"], rep["dead_code"], rep["recursion"],
                rep["circular_modules"], rep["vulns"], rep["secrets"])):
        add("\n   No issues surfaced by the current checks. ✓")
    add("=" * 66)
    return "\n".join(L)


def report_to_markdown(rep):
    """Render a report dict as Markdown (paste-ready for a project write-up)."""
    M = []
    add = M.append
    add(f"# Static Analysis Report — {rep['title']}\n")
    add(f"*Language:* `{rep['language']}`  ·  *Nodes:* {rep['node_count']}  "
        f"·  *Edges:* {rep['edge_count']}  ·  *Functions/Methods:* "
        f"{rep['n_functions']}\n")
    add(f"*Cyclomatic complexity:* average **{rep['avg_complexity']}**, "
        f"maximum **{rep['max_complexity']}**\n")

    add("\n## Kind breakdown\n")
    add("| Kind | Count |\n|---|---|")
    for k, v in sorted(rep["counts"].items()):
        add(f"| {k} | {v} |")

    if rep["hotspots"]:
        add("\n## Complexity hotspots (McCabe ≥ 8)\n")
        add("| Complexity | Function | Line |\n|---|---|---|")
        for f in rep["hotspots"]:
            add(f"| {f['complexity']} | `{f['label']}` | {f['line'] or ''} |")

    if rep["dead_code"]:
        add("\n## Possibly-unused code\n")
        add("> Heuristic — no static caller was found. Dynamic dispatch, "
            "framework callbacks or reflection may still invoke these.\n")
        add("| Kind | Name | Line |\n|---|---|---|")
        for f in rep["dead_code"][:40]:
            add(f"| {f['kind']} | `{f['label']}` | {f['line'] or ''} |")

    if rep["recursion"]:
        add("\n## Recursion / call cycles\n")
        for cyc in rep["recursion"][:15]:
            add(f"- {' → '.join(f'`{c}`' for c in cyc)}"
                + (" → …" if len(cyc) > 1 else " *(self-recursive)*"))

    if rep["circular_modules"]:
        add("\n## Circular module dependencies\n")
        for cyc in rep["circular_modules"]:
            add(f"- {' → '.join(f'`{c}`' for c in cyc)} → …")

    if rep["vulns"]:
        add("\n## Security — dangerous calls (SAST)\n")
        add("| Severity | Call | Line | CWE |\n|---|---|---|---|")
        for v in rep["vulns"]:
            add(f"| {v['severity']} | `{v['label']}` | {v['line'] or ''} "
                f"| {v['cwe'] or ''} |")

    if rep["secrets"]:
        add("\n## Security — hardcoded secrets\n")
        add("| Line | Type | Snippet |\n|---|---|---|")
        for s in rep["secrets"]:
            add(f"| {s['line']} | {s['label']} | `{s.get('snippet','')}` |")

    if rep["ports"] or rep["root_procs"]:
        add("\n## System exposure\n")
        if rep["ports"]:
            add(f"- Listening ports: {', '.join(sorted(set(rep['ports']))[:20])}")
        if rep["root_procs"]:
            add(f"- Root/SYSTEM processes shown: {len(rep['root_procs'])}")

    add("\n---\n*Generated by NeuralSchema. SAST and secret checks are "
        "heuristic first-pass aids, not a substitute for manual review.*")
    return "\n".join(M)


def export_report(sg, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_to_markdown(build_report(sg)))
    return out_path


def draw_schema(ax, sg, pos, highlight=None, max_labels=45):
    """Draw the schema onto a matplotlib Axes.

    Returns (scatter_artist, node_order) so callers can wire up pick events.
    """
    from matplotlib.collections import LineCollection
    from matplotlib.lines import Line2D

    ax.clear()
    ax.set_facecolor("#0d1117")
    ax.figure.set_facecolor("#0d1117")
    ax.set_xticks([]); ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)

    nodes = sg.nodes()
    deg = sg.degree()
    highlight = highlight or set()
    hl_active = bool(highlight)
    focus = set(highlight)
    if hl_active:
        for h in list(highlight):
            focus |= sg.neighbors(h)

    # ---- edges ----
    seg_by_style = defaultdict(list)
    for (s, d, r) in sg.edges():
        if s not in pos or d not in pos or s == d:   # self-edges: invisible
            continue
        color, ls = REL_STYLE.get(r, ("#484f58", "solid"))
        dim = hl_active and not (s in focus and d in focus)
        seg_by_style[(color, ls, dim)].append([pos[s], pos[d]])
    for (color, ls, dim), segs in seg_by_style.items():
        lc = LineCollection(segs, colors=color, linewidths=0.7,
                            linestyles=ls, alpha=0.12 if dim else 0.55,
                            zorder=1)
        ax.add_collection(lc)

    # ---- nodes ----
    order = list(nodes.keys())
    xs = [pos[n][0] for n in order if n in pos]
    ys = [pos[n][1] for n in order if n in pos]
    order = [n for n in order if n in pos]
    colors, sizes, edgecolors, lws = [], [], [], []
    for n in order:
        kind = nodes[n]["kind"]
        base = KIND_COLOR.get(kind, "#8b949e")
        d = deg.get(n, 0)
        size = 90 + 55 * (d ** 0.6)
        if kind in (K_PROJECT, K_MODULE, K_SYSTEM):
            size = max(size, 420)
        # security nodes read a little bigger so they don't get lost
        if kind in (K_VULN, K_PORT):
            size = max(size, 200)
        dim = hl_active and n not in focus
        colors.append(base if not dim else "#30363d")
        sizes.append(size)
        privileged = nodes[n].get("privileged")
        if hl_active and n in highlight:
            edgecolors.append("#ffffff"); lws.append(2.2)
        elif privileged and not dim:              # root/SYSTEM process -> red ring
            edgecolors.append("#ff3860"); lws.append(2.0)
        else:
            edgecolors.append("#0d1117"); lws.append(0.6)

    scatter = ax.scatter(xs, ys, c=colors, s=sizes, edgecolors=edgecolors,
                         linewidths=lws, zorder=3, picker=5)

    # ---- labels ----
    if hl_active:
        to_label = focus
    elif len(order) <= max_labels:
        to_label = set(order)
    else:
        # label the most connected nodes + structural roots
        ranked = sorted(order, key=lambda n: deg.get(n, 0), reverse=True)
        to_label = set(ranked[:max_labels])
        to_label |= {n for n in order if nodes[n]["kind"] in
                     (K_PROJECT, K_MODULE, K_SYSTEM, K_NAMESPACE)}
    for n in order:
        if n not in to_label:
            continue
        label = nodes[n]["label"]
        if len(label) > 26:
            label = label[:24] + "…"
        ax.annotate(label, pos[n], fontsize=7.0, color="#c9d1d9",
                    ha="center", va="center",
                    xytext=(0, 9), textcoords="offset points", zorder=4)

    # ---- legend (kinds actually present) ----
    present = sorted({nodes[n]["kind"] for n in order},
                     key=lambda k: list(KIND_COLOR).index(k)
                     if k in KIND_COLOR else 999)
    handles = [Line2D([0], [0], marker="o", linestyle="",
                      markerfacecolor=KIND_COLOR.get(k, "#8b949e"),
                      markeredgecolor="#0d1117", markersize=8, label=k)
               for k in present]
    if handles:
        leg = ax.legend(handles=handles, loc="upper left", fontsize=7.5,
                        framealpha=0.15, facecolor="#161b22",
                        edgecolor="#30363d", labelcolor="#c9d1d9",
                        ncol=1 if len(handles) <= 8 else 2)
        leg.set_zorder(5)

    ax.margins(0.08)
    return scatter, order


# ============================================================================
#  Exporters
# ============================================================================

def export_json(sg, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sg.to_dict(), f, indent=2, default=str)
    return out_path


def export_png(sg, out_path, algo="spring", dpi=160):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(15, 10))
    pos = compute_layout(sg, algo)
    draw_schema(ax, sg, pos)
    title = f"{sg.title}"
    if sg.language and sg.language != "mixed":
        title += f"  ·  {sg.language}"
    ax.set_title(title, color="#c9d1d9", fontsize=13, pad=14)
    fig.tight_layout()
    fig.savefig(out_path, dpi=dpi, facecolor="#0d1117")
    plt.close(fig)
    return out_path


def export_html(sg, out_path, algo="spring"):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    if not _PYVIS_OK:
        data_json = json.dumps(sg.to_dict(), indent=2, default=str)
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>NeuralSchema &mdash; {sg.title}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 24px; }}
h1, h2 {{ color: #58a6ff; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin-bottom: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
th {{ background: #21262d; color: #f0f6fc; }}
pre {{ background: #040d21; padding: 12px; border-radius: 4px; overflow-x: auto; color: #7ee787; }}
</style>
</head>
<body>
<h1>NeuralSchema Architecture: {sg.title}</h1>
<div class="card">
  <h2>Metadata</h2>
  <p><strong>Nodes:</strong> {len(sg.nodes())} &nbsp;|&nbsp; <strong>Edges:</strong> {len(sg.edges())} &nbsp;|&nbsp; <strong>Language:</strong> {sg.language or 'auto'}</p>
</div>
<div class="card">
  <h2>Graph Data (JSON)</h2>
  <pre id="data">{data_json}</pre>
</div>
</body>
</html>"""
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return out_path

    net = Network(height="820px", width="100%", directed=True,
                  bgcolor="#0d1117", font_color="#c9d1d9",
                  cdn_resources="in_line")
    net.barnes_hut(gravity=-14000, spring_length=110, spring_strength=0.02)
    deg = sg.degree()
    nodes = sg.nodes()
    for nid, attrs in nodes.items():
        kind = attrs["kind"]
        d = deg.get(nid, 0)
        size = 12 + 6 * (d ** 0.5)
        if kind in (K_PROJECT, K_MODULE, K_SYSTEM):
            size = max(size, 34)
        tip = f"<b>{attrs['label']}</b><br>kind: {kind}"
        for k, v in attrs.items():
            if k in ("kind", "label"):
                continue
            tip += f"<br>{k}: {v}"
        base = KIND_COLOR.get(kind, "#8b949e")
        shape = "dot"
        color = base
        if kind in (K_VULN, K_PORT):
            shape = "star"
            size = max(size, 18)
        if attrs.get("privileged"):
            # keep fill colour but draw a red border to flag root/SYSTEM
            color = {"background": base, "border": "#ff3860"}
        net.add_node(nid, label=attrs["label"], title=tip, color=color,
                     size=size, shape=shape, borderWidth=3 if
                     attrs.get("privileged") else 1)
    for (s, d, r) in sg.edges():
        if s in nodes and d in nodes:
            color, ls = REL_STYLE.get(r, ("#484f58", "solid"))
            dashes = ls != "solid"
            net.add_edge(s, d, title=r, color=color, dashes=dashes, arrows="to")
    # pyvis writes relative to cwd; make sure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    net.save_graph(out_path)
    return out_path


# ============================================================================
#  CRAWL MODE  --  "watch a crawler explore the schema"
# ============================================================================
#
#  WHY THIS EXISTS
#  ---------------
#  The normal views show the *finished* graph all at once.  For a big project
#  that is a hairball -- you see everything and understand nothing.  Crawl
#  Mode shows the SAME graph being *discovered* one node at a time, the way a
#  search-engine crawler walks the web: start at a root, follow every link
#  (here: contains / imports / calls / inherits / process-parent ...), queue
#  what you find, repeat.  Watching the order of discovery teaches you the
#  structure: what hangs off what, how deep the call chains go, which nodes
#  are hubs.
#
#  WHAT IS IN THIS SECTION (and where each piece flows next)
#  ---------------------------------------------------------
#   1. WebCrawler      -> a real, polite website crawler (robots.txt, delay,
#                         page cap).  Produces a normal SchemaGraph, so every
#                         other NeuralSchema export (json/html/png/report)
#                         also works on websites.            -> build_from_args
#   2. crawl_order()   -> turns ANY SchemaGraph into an ordered list of
#                         "discovery steps" (BFS, DFS, or a replay of the real
#                         web crawl).                         -> export_crawl
#   3. export_crawl()  -> writes ONE self-contained, offline HTML page that
#                         animates those steps on a canvas (the reel look:
#                         black canvas, neon link-tags, crawler heads).
#                                                             -> CLI / GUI
#
#  Only the Python standard library is used here (urllib, html.parser,
#  robotparser) so Crawl Mode adds ZERO new dependencies.
# ----------------------------------------------------------------------------

import hashlib                          # content fingerprint -> duplicate pages
import html as _html                    # escaping the page <title>
import time as _time                    # polite delay between requests
from collections import deque           # BFS queue / DFS stack for the crawler
from html.parser import HTMLParser      # stdlib HTML parser -> link extraction
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

# --- new node kinds / relation for website graphs ---------------------------
# Added to the SAME palette dicts the rest of the tool uses, so the Tkinter
# GUI, PNG and pyvis exporters colour web graphs correctly for free.
K_PAGE = "page"        # one URL on the crawled site
K_SITE = "site"        # an OFF-site host that pages link to (aggregated)
R_LINKS = "links-to"   # page --<a href>--> page / site
KIND_COLOR[K_PAGE] = "#58a6ff"
KIND_COLOR[K_SITE] = "#f778ba"
REL_STYLE[R_LINKS] = ("#1f6feb", "solid")

# Honest User-Agent: site owners can see who we are and block us in
# robots.txt if they want.  Never pretend to be a browser.
CRAWLER_UA = ("NeuralSchemaCrawler/1.0 "
              "(+https://github.com/Kanak234/neuralschema)")


def _update_node(sg, nid, **attrs):
    """Change attributes of a node that already exists.

    WHY: SchemaGraph.add_node() deliberately never overwrites (first writer
    wins).  The crawler, however, learns things about a page AFTER it first
    saw the link (its <title>, HTTP status...), so it needs a real update.
    Keeps the fallback dict and the networkx graph in sync.
    """
    if nid not in sg._nodes:
        return
    sg._nodes[nid].update(attrs)
    if sg.g is not None and nid in sg.g:
        sg.g.nodes[nid].update(attrs)


def normalize_url(base, href):
    """Resolve `href` against `base` and canonicalise it, or return None.

    WHY: the same page is reachable as "/a", "/a#top", "HTTP://Host:80/a" ...
    Without canonical URLs the crawler would fetch one page many times and
    the graph would show duplicates.  Non-web schemes (mailto:, javascript:,
    tel:, data:) are dropped -- they are not pages.
    """
    href = (href or "").strip()
    if not href or href.startswith("#"):
        return None
    if href.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None
    try:
        url = urldefrag(urljoin(base, href))[0]      # absolute, no #fragment
        p = urlparse(url)
    except ValueError:                               # e.g. bad IPv6 literal
        return None
    if p.scheme.lower() not in ("http", "https") or not p.netloc:
        return None
    netloc = p.netloc.lower()
    # drop default ports so http://x:80/ == http://x/
    if (p.scheme.lower() == "http" and netloc.endswith(":80")) or \
       (p.scheme.lower() == "https" and netloc.endswith(":443")):
        netloc = netloc.rsplit(":", 1)[0]
    return p._replace(scheme=p.scheme.lower(), netloc=netloc,
                      path=p.path or "/").geturl()


class _LinkExtractor(HTMLParser):
    """Collects <a href>, the <title>, and a page-level `nofollow` flag.

    WHY a stdlib parser and not regex: real HTML is messy; HTMLParser copes
    with broken markup and decodes &amp; entities for us.
    Flows into: WebCrawler.crawl(), which normalises every href.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._title = []
        self._in_title = False
        self.nofollow = False          # <meta name="robots" content="nofollow">

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            # respect per-link rel="nofollow" as well
            if "nofollow" not in a.get("rel", "").lower():
                self.links.append(a["href"])
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("name", "").lower() == "robots":
            if "nofollow" in a.get("content", "").lower():
                self.nofollow = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self._title.append(data)

    @property
    def title(self):
        return " ".join("".join(self._title).split())[:120]


class WebCrawler:
    """A small, POLITE website crawler that outputs a SchemaGraph.

    Politeness rules (these are what separate a crawler from an attack tool):
      * obeys robots.txt (and its Crawl-delay) for every host,
      * waits `delay` seconds between requests (default 1 s),
      * stops after `max_pages` fetches,
      * sends an honest User-Agent,
      * only reads the first `max_bytes` of a page and only parses HTML.

    Every discovered URL becomes a node carrying `disc_step`, `disc_parent`
    and `depth`.  crawl_order(strategy="replay") uses exactly those fields to
    replay the REAL crawl order in the animation.
    """

    def __init__(self, max_pages=40, same_domain=True, delay=1.0, timeout=10,
                 strategy="bfs", max_external=30, respect_robots=True,
                 user_agent=CRAWLER_UA, max_bytes=2_000_000,
                 max_links_per_page=200):
        self.max_pages = max(1, int(max_pages))
        self.same_domain = same_domain
        self.delay = max(0.0, float(delay))
        self.timeout = timeout
        self.strategy = "dfs" if strategy == "dfs" else "bfs"
        self.max_external = max_external
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.max_bytes = max_bytes
        self.max_links_per_page = max_links_per_page
        self._robots = {}        # "scheme://host" -> RobotFileParser
        self._host_delay = {}    # "scheme://host" -> Crawl-delay from robots
        self._last_hit = {}      # "scheme://host" -> time of last request

    # -- networking ---------------------------------------------------------
    def _fetch(self, url, max_bytes=None):
        """GET one URL.  Returns (status, content_type, body|None, final_url,
        error|None).  Never raises -- a crawler must survive bad pages."""
        cap = max_bytes or self.max_bytes
        req = Request(url, headers={
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"})
        try:
            with urlopen(req, timeout=self.timeout) as r:
                ctype = r.headers.get("Content-Type", "") or ""
                body = r.read(cap + 1)[:cap]
                return r.status, ctype, body, r.geturl(), None
        except HTTPError as e:
            ctype = (e.headers.get("Content-Type", "") if e.headers else "") or ""
            return e.code, ctype, None, url, f"HTTP {e.code}"
        except (URLError, socket.timeout, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            return None, "", None, url, str(reason)

    def _host_key(self, url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _allowed(self, url):
        """True if robots.txt lets us fetch `url` (cached per host).

        Status handling follows common crawler practice:
          200      -> parse the rules
          401/403  -> the site is protecting itself: disallow everything
          other 4xx (e.g. 404) -> no robots.txt: everything allowed
          5xx / network error  -> unknown: be conservative, disallow
        """
        if not self.respect_robots:
            return True
        key = self._host_key(url)
        rp = self._robots.get(key)
        if rp is None:
            rp = RobotFileParser()
            status, _ct, body, _u, _err = self._fetch(key + "/robots.txt",
                                                      max_bytes=500_000)
            self._last_hit[key] = _time.monotonic()
            if status == 200 and body is not None:
                rp.parse(body.decode("utf-8", "replace").splitlines())
            elif status in (401, 403):
                rp.disallow_all = True
            elif status is not None and 400 <= status < 500:
                rp.allow_all = True
            else:
                rp.disallow_all = True
            try:
                cd = rp.crawl_delay(self.user_agent)
                if cd:
                    self._host_delay[key] = float(cd)
            except Exception:
                pass
            self._robots[key] = rp
        return rp.can_fetch(self.user_agent, url)

    def _wait_turn(self, url):
        """Sleep so that requests to one host are at least `delay` apart
        (or the robots Crawl-delay, whichever is larger)."""
        key = self._host_key(url)
        gap = max(self.delay, self._host_delay.get(key, 0.0))
        last = self._last_hit.get(key)
        if last is not None and gap > 0:
            wait = gap - (_time.monotonic() - last)
            if wait > 0:
                _time.sleep(wait)
        self._last_hit[key] = _time.monotonic()

    # -- the crawl itself ---------------------------------------------------
    def crawl(self, start_url, progress=None):
        """Crawl from `start_url`; return a SchemaGraph of pages and links.

        progress(fetched, max_pages, url) is called after every fetch so the
        CLI can show a live counter.
        """
        start = normalize_url(start_url, start_url)
        if start is None:
            raise ValueError(f"not an http(s) URL: {start_url!r}")
        root_host = urlparse(start).netloc
        sg = SchemaGraph(title=f"crawl {root_host}", kind="web",
                         language="html", source=start)

        disc = [0]                      # discovery counter (list = mutable)
        content_seen = {}               # sha1(page bytes) -> first node id
        seen_edges = set()
        site_nodes = {}                 # off-site host -> node id

        def pid(u):
            return "url:" + u

        def discover(u, parent_id, depth):
            """Register a NEW url as a node, remembering how we found it."""
            p = urlparse(u)
            label = (p.path + ("?" + p.query if p.query else "")) or "/"
            if p.netloc != root_host:
                label = p.netloc + label
            sg.add_node(pid(u), K_PAGE, label[:80], url=u, depth=depth,
                        disc_step=disc[0], disc_parent=parent_id,
                        disc_relation=R_LINKS if parent_id else None,
                        status="queued", fetched=False)
            disc[0] += 1

        def link(src, dst):
            if (src, dst) not in seen_edges:
                seen_edges.add((src, dst))
                sg.add_edge(src, dst, R_LINKS)

        discover(start, None, 0)
        frontier = deque([(start, 0)])
        seen = {start}
        fetched = 0

        while frontier and fetched < self.max_pages:
            # BFS takes the OLDEST url (wide, level by level);
            # DFS takes the NEWEST (dives down one path first).
            url, depth = (frontier.popleft() if self.strategy == "bfs"
                          else frontier.pop())
            nid = pid(url)
            if not self._allowed(url):
                _update_node(sg, nid, status="blocked by robots.txt",
                             blocked=True)
                continue

            self._wait_turn(url)
            status, ctype, body, final_url, err = self._fetch(url)
            fetched += 1
            _update_node(sg, nid, fetched=True, fetch_order=fetched,
                         status=status if status is not None else "error",
                         content_type=ctype.split(";")[0].strip(),
                         **({"error": err} if err else {}))
            if progress:
                progress(fetched, self.max_pages, url)

            if body is None or ("html" not in ctype.lower() and ctype):
                continue                # images, PDFs, errors: leaf nodes

            # Same bytes under a different URL ("/" vs "/index.html", tracking
            # params...)?  Real crawlers de-duplicate by content; we mark it
            # and do not follow its links twice.
            digest = hashlib.sha1(body).hexdigest()
            twin = content_seen.get(digest)
            if twin is not None:
                _update_node(sg, nid, duplicate_of=sg.nodes()[twin].get("url"))
                continue
            content_seen[digest] = nid

            # decode with the server's charset if it told us one
            charset = "utf-8"
            if "charset=" in ctype.lower():
                charset = ctype.lower().split("charset=")[-1].split(";")[0].strip() or "utf-8"
            try:
                text = body.decode(charset, "replace")
            except LookupError:
                text = body.decode("utf-8", "replace")

            parser = _LinkExtractor()
            try:
                parser.feed(text)
            except Exception:
                pass                    # keep whatever was parsed
            if parser.title:
                _update_node(sg, nid, label=parser.title[:80],
                             title=parser.title)
            if parser.nofollow:
                _update_node(sg, nid, nofollow=True)
                continue

            base = final_url or url
            for href in parser.links[: self.max_links_per_page]:
                u = normalize_url(base, href)
                if u is None:
                    continue
                host = urlparse(u).netloc
                if self.same_domain and host != root_host:
                    # off-site: ONE node per host, never fetched
                    sid = site_nodes.get(host)
                    if sid is None:
                        if len(site_nodes) >= self.max_external:
                            continue
                        sid = "site:" + host
                        site_nodes[host] = sid
                        sg.add_node(sid, K_SITE, host, url=f"https://{host}/",
                                    depth=depth + 1, disc_step=disc[0],
                                    disc_parent=nid, disc_relation=R_LINKS)
                        disc[0] += 1
                    link(nid, sid)
                    continue
                if u not in seen:
                    seen.add(u)
                    discover(u, nid, depth + 1)
                    frontier.append((u, depth + 1))
                link(nid, pid(u))

        # anything still queued was skipped because of the page cap
        for url, _d in frontier:
            n = sg.nodes().get(pid(url))
            if n is not None and not n.get("fetched") and not n.get("blocked"):
                _update_node(sg, pid(url), status="not crawled (page cap)")
        return sg


# ----------------------------------------------------------------------------
#  crawl_order -- turn any graph into a sequence of discovery steps
# ----------------------------------------------------------------------------

# Which node a crawl should START from (lower = better root).
_ROOT_RANK = {K_PROJECT: 0, K_SYSTEM: 0, K_MODULE: 1, K_PAGE: 1,
              K_NAMESPACE: 2, K_CLASS: 3, K_STRUCT: 3, K_INTERFACE: 3}
# In which order a node's neighbours are visited (lower = first), so the
# crawl reads naturally: modules, then types, then functions, then the rest.
_VISIT_RANK = {K_MODULE: 0, K_NAMESPACE: 1, K_CLASS: 2, K_STRUCT: 2,
               K_INTERFACE: 2, K_FUNCTION: 3, K_METHOD: 3, K_PAGE: 3,
               K_IMPORT: 5, K_EXTERNAL: 6, K_SITE: 6, K_VULN: 4}


def crawl_order(sg, strategy="bfs", start=None):
    """Return the order in which a crawler would discover `sg`'s nodes.

    Each step is a dict: {"id", "parent", "rel", "depth", "out"}; parent is
    None for a root.  "out" is False when the crawler walked an edge
    BACKWARDS (e.g. reached a function from something it calls) so the
    viewer can say "called by" instead of "calls".  EVERY node appears exactly once (disconnected islands get
    their own new root), so the animation always ends with the full graph.

    strategy:
      "bfs"    -- breadth-first: whole level, then the next (wide wave)
      "dfs"    -- depth-first : follow one chain to the bottom, then back up
      "replay" -- the real order a WebCrawler found things (needs disc_step
                  on every node; otherwise falls back to "bfs")
    Edges are walked in BOTH directions (callers are reachable from callees)
    but outgoing edges are preferred, so the crawl follows the arrows first.
    """
    nodes = sg.nodes()
    if not nodes:
        return []

    if strategy == "replay":
        if all("disc_step" in a for a in nodes.values()):
            out = []
            for nid, a in sorted(nodes.items(), key=lambda kv: kv[1]["disc_step"]):
                par = a.get("disc_parent")
                out.append({"id": nid,
                            "parent": par if par in nodes else None,
                            "rel": a.get("disc_relation") if par in nodes else None,
                            "depth": int(a.get("depth", 0)), "out": True})
            return out
        strategy = "bfs"

    # adjacency: node -> [(neighbour, relation, is_outgoing)]
    adj = defaultdict(list)
    for s, d, r in sg.edges():
        if s in nodes and d in nodes and s != d:
            adj[s].append((d, r, True))
            adj[d].append((s, r, False))

    def nb_key(item):
        nb, _r, outgoing = item
        a = nodes[nb]
        return (not outgoing, _VISIT_RANK.get(a["kind"], 7),
                str(a["label"]).lower(), str(nb))

    for k in list(adj):
        uniq, seen_nb = [], set()
        for item in sorted(adj[k], key=nb_key):
            if item[0] not in seen_nb:          # keep the best edge per pair
                seen_nb.add(item[0])
                uniq.append(item)
        adj[k] = uniq

    deg = sg.degree()
    seeds = sorted(nodes, key=lambda n: (_ROOT_RANK.get(nodes[n]["kind"], 9),
                                         -deg.get(n, 0),
                                         str(nodes[n]["label"]).lower(), str(n)))
    if start is not None:
        # accept an id or a label
        if start not in nodes:
            match = [n for n, a in nodes.items() if a["label"] == start]
            start = match[0] if match else None
        if start is not None:
            seeds.insert(0, start)

    visited, steps = set(), []
    for seed in seeds:
        if seed in visited:
            continue
        visited.add(seed)
        steps.append({"id": seed, "parent": None, "rel": None, "depth": 0,
                      "out": True})
        if strategy == "dfs":
            # iterative pre-order DFS (no recursion limit on deep call chains)
            stack = [(seed, iter(adj[seed]), 0)]
            while stack:
                n, it, dp = stack[-1]
                for nb, r, o in it:
                    if nb not in visited:
                        visited.add(nb)
                        steps.append({"id": nb, "parent": n, "rel": r,
                                      "depth": dp + 1, "out": o})
                        stack.append((nb, iter(adj[nb]), dp + 1))
                        break
                else:
                    stack.pop()            # all neighbours done -> backtrack
        else:
            q = deque([(seed, 0)])
            while q:
                n, dp = q.popleft()
                for nb, r, o in adj[n]:
                    if nb not in visited:
                        visited.add(nb)
                        steps.append({"id": nb, "parent": n, "rel": r,
                                      "depth": dp + 1, "out": o})
                        q.append((nb, dp + 1))
    return steps


# ----------------------------------------------------------------------------
#  export_crawl -- the animated, offline HTML page
# ----------------------------------------------------------------------------

def _find_logo(logo_path=None):
    """Locate Kanak's KP watermark (logo-mark.svg).

    Looks at an explicit path, then next to this script, then the current
    folder.  Returns a data: URI or None (the page then shows a text badge).
    """
    import base64
    cands = [logo_path] if logo_path else []
    cands += [os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "logo-mark.svg"),
              os.path.join(os.getcwd(), "logo-mark.svg")]
    for c in cands:
        if c and os.path.isfile(c):
            with open(c, "rb") as f:
                raw = f.read(512_000)
            return "data:image/svg+xml;base64," + base64.b64encode(raw).decode()
    return None


def crawl_payload(sg, algo="spring", strategies=("bfs", "dfs"), logo_path=None):
    """Pack the graph + discovery orders into compact JSON-able data.

    Nodes/edges/steps are stored as index arrays (not long id strings) so a
    2,000-node project still produces a small file that loads instantly.
    """
    nodes = sg.nodes()
    ids = list(nodes)
    index = {nid: i for i, nid in enumerate(ids)}

    # layout -> plain floats normalised into [-1, 1] keeping the aspect ratio
    pos = compute_layout(sg, algo) if ids else {}
    xs = [float(pos[n][0]) for n in ids] or [0.0]
    ys = [float(pos[n][1]) for n in ids] or [0.0]
    cx, cy = (max(xs) + min(xs)) / 2, (max(ys) + min(ys)) / 2
    span = max(max(xs) - min(xs), max(ys) - min(ys)) / 2 or 1.0

    kinds = sorted({a["kind"] for a in nodes.values()})
    rels = sorted({r for _s, _d, r in sg.edges()} | {R_LINKS})
    kind_i = {k: i for i, k in enumerate(kinds)}
    rel_i = {r: i for i, r in enumerate(rels)}

    def short(v, n=160):
        s = str(v)
        return s if len(s) <= n else s[: n - 1] + "…"

    out_nodes = []
    for i, nid in enumerate(ids):
        a = nodes[nid]
        meta = {k: short(v) for k, v in a.items()
                if k not in ("kind", "label", "disc_step", "disc_parent",
                             "disc_relation") and v not in (None, "")}
        meta = dict(list(meta.items())[:14])
        out_nodes.append([round((xs[i] - cx) / span, 4),
                          round(-(ys[i] - cy) / span, 4),   # y up -> screen
                          kind_i[a["kind"]], short(a["label"], 60), meta])

    edges = [[index[s], index[d], rel_i[r]] for s, d, r in sg.edges()
             if s in index and d in index and s != d]

    orders = {}
    want = list(strategies)
    if all("disc_step" in a for a in nodes.values()) and nodes:
        want = ["replay"] + [s for s in want if s != "replay"]
    for st in want:
        steps = crawl_order(sg, st)
        orders[st] = [[index[s["id"]],
                       index[s["parent"]] if s["parent"] is not None else -1,
                       rel_i.get(s["rel"], -1) if s["rel"] else -1,
                       s["depth"], 1 if s.get("out", True) else 0]
                      for s in steps]

    return {
        "title": sg.title, "kind": sg.kind, "language": sg.language,
        "source": short(sg.source or "", 200),
        "kinds": kinds,
        "kindColors": [KIND_COLOR.get(k, "#8b949e") for k in kinds],
        "rels": rels,
        "relColors": [REL_STYLE.get(r, ("#484f58", "solid"))[0] for r in rels],
        "nodes": out_nodes, "edges": edges, "orders": orders,
        "logo": _find_logo(logo_path),
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
    }


def export_crawl(sg, out_path, algo="spring", strategy="bfs", logo_path=None):
    """Write the animated crawl page for `sg` to `out_path` (one .html file).

    The page needs no internet and no server: double-click it.
    `strategy` only picks which order plays first; the viewer can switch.
    """
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    data = crawl_payload(sg, algo=algo, logo_path=logo_path)
    if strategy in data["orders"]:
        data["initial"] = strategy
    else:
        data["initial"] = next(iter(data["orders"]), "bfs")
    # A raw "<" must never appear inside <script>: a node label like
    # "</script><script>alert(1)" (or "<!--") would otherwise break out of
    # the JSON block.  < is the same character to JSON.parse, but
    # invisible to the HTML parser.  Same for ">" and "&" for good measure.
    blob = (json.dumps(data, separators=(",", ":"), default=str,
                       ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))
    page = (_CRAWL_TEMPLATE
            .replace("__TITLE__", _html.escape(f"NeuralSchema crawl — {sg.title}"))
            .replace("__DATA__", blob))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    return out_path


# The template lives in its own file-level string so the Python above stays
# readable.  It is plain HTML/CSS/JS -- no CDN, works fully offline.
_CRAWL_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<meta name="description" content="Animated crawl of a NeuralSchema architecture graph, generated offline by NeuralSchema.">
<style>
/* ------------------------------------------------------------------
   Look: the reel -- pure black canvas, white headline, neon tags.
   All colours are tokens so the page stays consistent.
   ------------------------------------------------------------------ */
:root{
  --bg:#000; --panel:rgba(10,12,18,.78); --line:rgba(255,255,255,.12);
  --text:#f0f3f8; --dim:#9aa4b2; --accent:#58a6ff; --hot:#ff3eb5;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);overflow:hidden}
canvas{position:fixed;inset:0;width:100%;height:100%;display:block;cursor:grab;touch-action:none}
canvas.drag{cursor:grabbing}
/* headline, top-left, like the reel */
#head{position:fixed;left:24px;top:20px;max-width:min(560px,calc(100vw - 48px));pointer-events:none}
#head h1{margin:0;font-weight:500;font-size:clamp(20px,3.2vw,34px);line-height:1.15;letter-spacing:-.01em}
#head p{margin:6px 0 0;color:var(--dim);font:12px var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* stats + log, top-right */
#hud{position:fixed;right:16px;top:16px;width:260px;background:var(--panel);border:1px solid var(--line);
  border-radius:10px;padding:12px 14px;font:12px var(--mono);backdrop-filter:blur(6px)}
#hud .row{display:flex;justify-content:space-between;gap:8px;margin:2px 0}
#hud .row b{color:var(--text);font-weight:600}
#hud .k{color:var(--dim)}
#bar{height:4px;background:rgba(255,255,255,.1);border-radius:2px;margin:8px 0 10px;overflow:hidden}
#bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--hot))}
#log{margin-top:8px;border-top:1px solid var(--line);padding-top:8px;height:118px;overflow:hidden}
#log div{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--dim);line-height:19px}
#log div:first-child{color:var(--text)}
#log span{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;vertical-align:0}
#legend{margin-top:8px;border-top:1px solid var(--line);padding-top:8px;display:flex;flex-wrap:wrap;gap:4px 10px;color:var(--dim)}
#legend span{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}
/* controls, bottom */
#ctl{position:fixed;left:50%;bottom:16px;transform:translateX(-50%);display:flex;flex-wrap:wrap;align-items:center;
  gap:8px 12px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:10px 14px;
  font:12px var(--sans);width:min(940px,calc(100vw - 32px));backdrop-filter:blur(6px)}
#ctl button,#ctl select{font:inherit;color:var(--text);background:#151a24;border:1px solid #2a3242;border-radius:8px;
  padding:7px 11px;cursor:pointer;min-height:34px}
#ctl button:hover,#ctl select:hover{border-color:var(--accent)}
#ctl button:focus-visible,#ctl select:focus-visible,#ctl input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
#ctl button.on{background:#1f3a66;border-color:var(--accent)}
#ctl label{display:flex;align-items:center;gap:6px;color:var(--dim)}
#ctl input[type=range]{accent-color:var(--accent);width:90px}
#tl{flex:1 1 180px;display:flex;align-items:center;gap:8px}
#tl input{flex:1;width:auto}
#tl output{font-family:var(--mono);color:var(--dim);min-width:84px;text-align:right}
/* node details, left */
#info{position:fixed;left:16px;bottom:96px;width:300px;max-height:45vh;overflow:auto;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;padding:12px 14px;font:12px var(--mono);display:none}
#info h2{margin:0 0 6px;font:600 14px var(--sans);word-break:break-word}
#info table{border-collapse:collapse;width:100%}
#info td{padding:2px 0;vertical-align:top;word-break:break-word}
#info td:first-child{color:var(--dim);padding-right:10px;white-space:nowrap}
#info .x{float:right;background:none;border:0;color:var(--dim);cursor:pointer;font-size:16px}
/* watermark */
#wm{position:fixed;right:16px;bottom:96px;display:flex;align-items:center;gap:6px;opacity:.55;font:11px var(--sans);
  color:var(--dim);pointer-events:none}
#wm img{height:22px;width:auto}
#wm b{display:inline-grid;place-items:center;width:22px;height:22px;border:1px solid var(--dim);border-radius:50%;font-size:9px;color:var(--text)}
#empty{position:fixed;inset:0;display:none;place-items:center;color:var(--dim);font:14px var(--sans)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
@media (max-width:760px){
  #hud{width:auto;left:16px;right:16px;top:104px;padding:8px 12px}
  #log,#legend{display:none}
  #head{top:14px;left:16px}
  #info{left:16px;right:16px;width:auto;bottom:186px;max-height:30vh}
  #wm{bottom:186px;right:16px}
  #ctl{bottom:10px;gap:6px 8px;padding:8px 10px}
  #ctl input[type=range]{width:70px}
}
</style>
</head>
<body>
<canvas id="cv" aria-label="Animated graph of a crawler discovering nodes" role="img"></canvas>
<div id="head"><h1 id="h1">This Animation Shows How a Crawler Explores Your Code</h1><p id="sub"></p></div>

<div id="hud" aria-live="off">
  <div class="row"><span class="k">discovered</span><b id="sDone">0</b></div>
  <div id="bar"><i></i></div>
  <div class="row"><span class="k">frontier (queued)</span><b id="sFront">0</b></div>
  <div class="row"><span class="k">depth</span><b id="sDepth">0</b></div>
  <div class="row"><span class="k">links followed</span><b id="sLinks">0</b></div>
  <div id="log"></div>
  <div id="legend"></div>
</div>

<div id="info" role="dialog" aria-label="Node details"><button class="x" id="infoX" aria-label="Close details">×</button><h2 id="iT"></h2><table id="iTab"></table></div>
<div id="wm"></div>
<div id="empty">Nothing to crawl — the schema has no nodes.</div>

<div id="ctl">
  <button id="bPlay" aria-label="Play or pause (Space)">❚❚ Pause</button>
  <button id="bRe" aria-label="Restart (R)">↺ Restart</button>
  <label>Order <select id="sMode" aria-label="Crawl order"></select></label>
  <label>Speed <input id="rSpeed" type="range" min="0" max="100" value="55" aria-label="Speed"></label>
  <label>Crawlers <input id="rW" type="range" min="1" max="8" value="3" aria-label="Parallel crawlers"></label>
  <button id="bFollow" class="on" aria-pressed="true" aria-label="Camera follows the crawl (F)">◎ Follow</button>
  <button id="bTags" class="on" aria-pressed="true" aria-label="Show link tags (T)">▭ Tags</button>
  <div id="tl"><input id="rT" type="range" min="0" max="1000" value="0" step="1" aria-label="Timeline"><output id="oT">0 / 0</output></div>
</div>
<p class="sr">Keyboard: Space play/pause, R restart, F follow, T tags, arrow keys step. Drag to pan, wheel to zoom, click a node for details.</p>

<script type="application/json" id="ns-data">__DATA__</script>
<script>
/* =====================================================================
   NeuralSchema · Crawl Mode player
   ---------------------------------------------------------------------
   DATA  (built by crawl_payload() in neural_schema.py)
     nodes  : [x, y, kindIndex, label, meta]   (x,y already in [-1,1])
     edges  : [srcIndex, dstIndex, relIndex]
     orders : {bfs|dfs|replay : [[node, parent, rel, depth, out], ...]}
              out = 1 if the edge was walked along its arrow, 0 if backwards
   TIME MODEL
     Step i STARTS at time i / W (W = parallel crawlers) and takes 1 time
     unit to travel parent -> node.  So at time t:
       done      = steps with  i/W + 1 <= t
       in flight = steps with  i/W <= t < i/W + 1
     Everything below (drawing, HUD, timeline) is a pure function of t,
     which is why scrubbing backwards "just works".
   ===================================================================== */
"use strict";
const D = JSON.parse(document.getElementById("ns-data").textContent);
const N = D.nodes.length;
const cv = document.getElementById("cv"), ctx = cv.getContext("2d");
const $ = id => document.getElementById(id);

/* ---- headline: reel wording, adapted to what we are crawling ---- */
const what = D.kind === "web" ? "a Website" : D.kind === "system" ? "Your System" : "Your Code";
$("h1").textContent = "This Animation Shows How a Crawler Explores " + what;
const srcTail = String(D.source || "").split(/[\\/]/).pop();
$("sub").textContent = (D.title || "") + (D.source && srcTail !== D.title && D.source !== D.title ? "  ·  " + D.source : "");

/* ---- watermark: Kanak's KP logo if embedded, else a text badge ---- */
(function(){
  const wm = $("wm");
  if (D.logo) { const im = new Image(); im.src = D.logo; im.alt = "KP"; wm.appendChild(im); }
  else { const b = document.createElement("b"); b.textContent = "KP"; wm.appendChild(b); }
  wm.appendChild(document.createTextNode("NeuralSchema"));
})();

if (!N) { $("empty").style.display = "grid"; $("hud").style.display = "none"; }

/* ---- per-node lookups used every frame ---- */
const X = new Float32Array(N), Y = new Float32Array(N), K = new Uint8Array(N);
D.nodes.forEach((n, i) => { X[i] = n[0]; Y[i] = n[1]; K[i] = n[2]; });
// stable pseudo-random per node (so tags keep their tilt between frames)
function hash(s){ let h = 2166136261; for (let i = 0; i < s.length; i++){ h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
const TILT = new Float32Array(N);
D.nodes.forEach((n, i) => { const h = hash(String(n[3]) + i); TILT[i] = (h % 6 === 0) ? ((h >> 4) % 2 ? 1 : -1) * (0.35 + ((h >> 8) % 30) / 100) : 0; });
// neighbour lists for the click-highlight
const NB = Array.from({length: N}, () => []);
D.edges.forEach(e => { NB[e[0]].push(e[1]); NB[e[1]].push(e[0]); });

/* ---- legend ---- */
D.kinds.forEach((k, i) => {
  const el = document.createElement("div"); const sw = document.createElement("span");
  sw.style.background = D.kindColors[i]; el.appendChild(sw); el.appendChild(document.createTextNode(k)); $("legend").appendChild(el);
});

/* ---- order selector ---- */
const NAMES = {bfs: "Breadth-first (BFS)", dfs: "Depth-first (DFS)", replay: "Real crawl (replay)"};
Object.keys(D.orders).forEach(k => { const o = document.createElement("option"); o.value = k; o.textContent = NAMES[k] || k; $("sMode").appendChild(o); });

/* =====================================================================
   STATE
   ===================================================================== */
const reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
let mode = D.initial || Object.keys(D.orders)[0] || "bfs";
let S = [];                 // current steps
let rank = new Int32Array(N);  // node -> step index (when it gets discovered)
let lastChild = new Int32Array(0); // step -> index of its last child step (for frontier)
let t = 0, playing = !reduce && N > 0, W = 3, speed = 6;
let follow = true, tags = N <= 1500, selected = -1;
let cam = {x: 0, y: 0, s: 1}, camT = {x: 0, y: 0, s: 1};
let dpr = 1, vw = 0, vh = 0;

function setMode(m){
  mode = m; S = D.orders[m] || [];
  rank.fill(-1);
  S.forEach((s, i) => { rank[s[0]] = i; });
  lastChild = new Int32Array(S.length).fill(-1);
  S.forEach((s, i) => { if (s[1] >= 0 && rank[s[1]] >= 0) lastChild[rank[s[1]]] = i; });
  $("sMode").value = m; t = 0; selected = -1; $("info").style.display = "none";
  // 1 crawler for tiny graphs looks best; many for huge ones so it finishes
  if (S.length > 1500 && W < 6) { W = 6; $("rW").value = 6; }
}
const totalT = () => S.length ? (S.length - 1) / W + 1 : 0;
function speedFromSlider(v){ return 0.4 * Math.pow(1.055, v); }      // 0.4 .. ~84 steps/s
speed = speedFromSlider(+$("rSpeed").value);
if (!tags) $("bTags").classList.remove("on");

/* =====================================================================
   CAMERA  world [-1,1] -> screen pixels
   ===================================================================== */
function resize(){
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  vw = innerWidth; vh = innerHeight;
  cv.width = vw * dpr; cv.height = vh * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
addEventListener("resize", resize); resize();
const base = () => Math.min(vw, vh) * 0.42;
const sx = x => vw / 2 + (x - cam.x) * cam.s * base();
const sy = y => vh / 2 + (y - cam.y) * cam.s * base();
const wx = px => (px - vw / 2) / (cam.s * base()) + cam.x;
const wy = py => (py - vh / 2) / (cam.s * base()) + cam.y;

/* =====================================================================
   DRAWING
   ===================================================================== */
const ease = u => u < 0 ? 0 : u > 1 ? 1 : 1 - Math.pow(1 - u, 3);
function rgba(hex, a){ const n = parseInt(hex.slice(1), 16); return `rgba(${n>>16&255},${n>>8&255},${n&255},${a})`; }
function roundRect(x, y, w, h, r){ ctx.beginPath(); ctx.moveTo(x+r, y); ctx.arcTo(x+w, y, x+w, y+h, r); ctx.arcTo(x+w, y+h, x, y+h, r); ctx.arcTo(x, y+h, x, y, r); ctx.arcTo(x, y, x+w, y, r); ctx.closePath(); }

function frame(){
  const T = totalT();
  const doneN = Math.max(0, Math.min(S.length, Math.floor((t - 1) * W) + 1));   // steps fully arrived
  const startN = Math.max(0, Math.min(S.length, Math.floor(t * W) + 1));       // steps started

  /* --- camera: fit everything discovered so far (+ in flight targets) --- */
  if (follow && S.length){
    let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    const upto = Math.max(1, startN);
    for (let i = 0; i < upto; i++){ const n = S[i][0]; if (X[n] < x0) x0 = X[n]; if (X[n] > x1) x1 = X[n]; if (Y[n] < y0) y0 = Y[n]; if (Y[n] > y1) y1 = Y[n]; }
    const w = Math.max(x1 - x0, 0.35), h = Math.max(y1 - y0, 0.35);
    camT.x = (x0 + x1) / 2; camT.y = (y0 + y1) / 2;
    camT.s = Math.min(2 / w * (vw / Math.min(vw, vh)) * 0.78, 2 / h * (vh / Math.min(vw, vh)) * 0.72, 5);
  }
  const k = reduce ? 1 : 0.07;
  cam.x += (camT.x - cam.x) * k; cam.y += (camT.y - cam.y) * k; cam.s += (camT.s - cam.s) * k;

  ctx.fillStyle = "#000"; ctx.fillRect(0, 0, vw, vh);

  /* --- 1. faint "other relations" between discovered nodes (context) --- */
  if (doneN > 1 && D.edges.length < 20000){
    ctx.lineWidth = 0.6; ctx.strokeStyle = "rgba(140,160,190,0.07)"; ctx.beginPath();
    for (const e of D.edges){ const a = rank[e[0]], b = rank[e[1]]; if (a >= 0 && b >= 0 && a < doneN && b < doneN){ ctx.moveTo(sx(X[e[0]]), sy(Y[e[0]])); ctx.lineTo(sx(X[e[1]]), sy(Y[e[1]])); } }
    ctx.stroke();
  }

  /* --- 2. discovery paths (the tree the crawler actually walked) --- */
  const recent = Math.max(0, doneN - W * 10);
  ctx.lineWidth = 0.9;
  for (let i = 0; i < doneN; i++){
    const s = S[i]; if (s[1] < 0) continue;
    const c = s[2] >= 0 ? D.relColors[s[2]] : "#58a6ff";
    const fresh = i >= recent ? 0.35 + 0.5 * (i - recent) / Math.max(1, doneN - recent) : 0.22;
    ctx.strokeStyle = rgba(c === "#484f58" || c === "#6e7681" ? "#8aa4ff" : c, fresh);
    ctx.beginPath(); ctx.moveTo(sx(X[s[1]]), sy(Y[s[1]])); ctx.lineTo(sx(X[s[0]]), sy(Y[s[0]])); ctx.stroke();
  }

  /* --- 3. every discovered node as a dot --- */
  for (let i = 0; i < doneN; i++){
    const n = S[i][0]; const c = D.kindColors[K[n]];
    ctx.fillStyle = c; ctx.beginPath(); ctx.arc(sx(X[n]), sy(Y[n]), i < 1 ? 4 : 2.4, 0, 6.2832); ctx.fill();
  }

  /* --- 4. crawlers in flight: glowing head travelling along a link --- */
  for (let i = doneN; i < startN; i++){
    const s = S[i], n = s[0], u = ease(t - i / W);
    const c = D.kindColors[K[n]];
    const px = s[1] >= 0 ? X[s[1]] : X[n], py = s[1] >= 0 ? Y[s[1]] : Y[n];
    const hx = sx(px + (X[n] - px) * u), hy = sy(py + (Y[n] - py) * u);
    ctx.strokeStyle = rgba(c, 0.9); ctx.lineWidth = 1.6;
    ctx.beginPath(); ctx.moveTo(sx(px), sy(py)); ctx.lineTo(hx, hy); ctx.stroke();
    ctx.save(); ctx.shadowColor = c; ctx.shadowBlur = 14; ctx.fillStyle = "#fff";
    ctx.beginPath(); ctx.arc(hx, hy, 3.2, 0, 6.2832); ctx.fill(); ctx.restore();
    // scan ring on the page the crawler is reading from
    ctx.strokeStyle = rgba(c, 0.5 * (1 - u)); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(sx(px), sy(py), 6 + 14 * u, 0, 6.2832); ctx.stroke();
  }

  /* --- 5. link tags: the reel's highlighted boxes on recent finds --- */
  ctx.font = "12px " + getComputedStyle(document.body).getPropertyValue("--mono");
  ctx.textBaseline = "middle";
  const maxTags = tags ? Math.min(48, 14 + W * 6) : 0;
  const from = Math.max(0, doneN - maxTags);
  for (let i = from; i < doneN; i++){
    const n = S[i][0], c = D.kindColors[K[n]];
    const age = doneN - 1 - i;                    // 0 = newest
    const pop = reduce ? 1 : ease((t - (i / W + 1)) * 4);
    const label = String(D.nodes[n][3]);
    const tw = Math.min(ctx.measureText(label).width, 220);
    const x = sx(X[n]) + 8, y = sy(Y[n]);
    ctx.save(); ctx.translate(x, y); ctx.rotate(TILT[n]); ctx.scale(0.6 + 0.4 * pop, 0.6 + 0.4 * pop);
    ctx.globalAlpha = Math.max(0.25, 1 - age / maxTags) * pop;
    roundRect(-3, -9, tw + 10, 18, 3);
    if (age < W){ ctx.fillStyle = c; ctx.fill(); ctx.fillStyle = "#05070b"; }   // newest: solid neon
    else { ctx.fillStyle = rgba(c, 0.14); ctx.fill(); ctx.strokeStyle = c; ctx.lineWidth = 1; ctx.stroke(); ctx.fillStyle = c; }
    ctx.beginPath(); ctx.rect(-3, -9, tw + 10, 18); ctx.clip();
    ctx.fillText(label, 2, 0.5);
    ctx.restore();
  }
  // small labels for older nodes once you zoom in enough to read them
  if (cam.s > 2.2 && doneN < 3000){
    ctx.globalAlpha = 0.55; ctx.font = "10px " + getComputedStyle(document.body).getPropertyValue("--mono");
    for (let i = 0; i < from; i++){ const n = S[i][0]; const x = sx(X[n]), y = sy(Y[n]);
      if (x > -50 && x < vw + 50 && y > -20 && y < vh + 20){ ctx.fillStyle = D.kindColors[K[n]]; ctx.fillText(String(D.nodes[n][3]).slice(0, 32), x + 5, y); } }
    ctx.globalAlpha = 1;
  }

  /* --- 6. selection highlight --- */
  if (selected >= 0 && rank[selected] >= 0 && rank[selected] < doneN){
    const x = sx(X[selected]), y = sy(Y[selected]);
    ctx.strokeStyle = "#fff"; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, 9, 0, 6.2832); ctx.stroke();
    ctx.strokeStyle = "rgba(255,255,255,.55)"; ctx.beginPath();
    for (const m of NB[selected]){ if (rank[m] >= 0 && rank[m] < doneN){ ctx.moveTo(x, y); ctx.lineTo(sx(X[m]), sy(Y[m])); } }
    ctx.stroke();
  }

  hud(doneN, T);
}

/* =====================================================================
   HUD  (throttled to ~8 Hz: DOM writes every frame would be wasteful)
   ===================================================================== */
let hudAt = 0, logAt = -1;
function hud(doneN, T){
  const now = performance.now(); if (now - hudAt < 120) return; hudAt = now;
  $("sDone").textContent = doneN + " / " + S.length;
  $("bar").firstChild.style.width = (S.length ? 100 * doneN / S.length : 0) + "%";
  // frontier = discovered nodes that still have undiscovered children (= the crawler's queue)
  let fr = 0, dep = 0, links = 0;
  for (let i = 0; i < doneN; i++){ if (lastChild[i] >= doneN) fr++; if (S[i][3] > dep) dep = S[i][3]; if (S[i][1] >= 0) links++; }
  $("sFront").textContent = fr; $("sDepth").textContent = dep; $("sLinks").textContent = links;
  $("rT").value = T ? Math.round(1000 * t / T) : 0;
  $("oT").textContent = doneN + " / " + S.length;
  if (logAt !== doneN){
    logAt = doneN; const lg = $("log"); lg.textContent = "";
    for (let i = doneN - 1; i >= Math.max(0, doneN - 6); i--){
      const s = S[i], n = s[0], d = document.createElement("div"), sw = document.createElement("span");
      sw.style.background = D.kindColors[K[n]]; d.appendChild(sw);
      d.appendChild(document.createTextNode((s[2] >= 0 ? D.rels[s[2]] + (s[4] ? " → " : " ← ") : "root · ") + D.nodes[n][3]));
      lg.appendChild(d);
    }
  }
  $("bPlay").textContent = playing ? "❚❚ Pause" : (t >= T ? "↺ Replay" : "▶ Play");
}

/* =====================================================================
   LOOP
   ===================================================================== */
let prev = performance.now();
function loop(now){
  const dt = Math.min(0.1, (now - prev) / 1000); prev = now;
  if (playing && S.length){
    t += dt * speed / W;            // speed is "nodes per second" regardless of W
    if (t >= totalT()){ t = totalT(); playing = false; }
  }
  frame();
  window.NS_STATE = {t, total: totalT(), steps: S.length, mode, playing};   // used by automated tests
  requestAnimationFrame(loop);
}

/* =====================================================================
   INPUT
   ===================================================================== */
function togglePlay(){ if (!playing && t >= totalT()) t = 0; playing = !playing; }
function setFollow(v){ follow = v; $("bFollow").classList.toggle("on", v); $("bFollow").setAttribute("aria-pressed", v); }
$("bPlay").onclick = togglePlay;
$("bRe").onclick = () => { t = 0; playing = true; setFollow(true); };
$("sMode").onchange = e => { setMode(e.target.value); playing = true; };
$("rSpeed").oninput = e => { speed = speedFromSlider(+e.target.value); };
$("rW").oninput = e => { const done = t * W; W = +e.target.value; t = done / W; };   // keep progress when W changes
$("bFollow").onclick = () => setFollow(!follow);
$("bTags").onclick = () => { tags = !tags; $("bTags").classList.toggle("on", tags); $("bTags").setAttribute("aria-pressed", tags); };
$("rT").oninput = e => { t = totalT() * (+e.target.value) / 1000; playing = false; };
$("infoX").onclick = () => { selected = -1; $("info").style.display = "none"; };
addEventListener("keydown", e => {
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;
  if (e.code === "Space"){ e.preventDefault(); togglePlay(); }
  else if (e.key === "r" || e.key === "R") $("bRe").click();
  else if (e.key === "f" || e.key === "F") setFollow(!follow);
  else if (e.key === "t" || e.key === "T") $("bTags").click();
  else if (e.key === "ArrowRight"){ playing = false; t = Math.min(totalT(), t + 1 / W); }
  else if (e.key === "ArrowLeft"){ playing = false; t = Math.max(0, t - 1 / W); }
  else if (e.key === "Escape") $("infoX").click();
});

// pan (drag) / zoom (wheel, pinch) / pick (click)
let drag = null, moved = false;
const pts = new Map();
cv.addEventListener("pointerdown", e => { cv.setPointerCapture(e.pointerId); pts.set(e.pointerId, [e.clientX, e.clientY]); drag = {x: e.clientX, y: e.clientY}; moved = false; cv.classList.add("drag"); });
cv.addEventListener("pointermove", e => {
  if (!pts.has(e.pointerId)) return;
  const old = pts.get(e.pointerId); pts.set(e.pointerId, [e.clientX, e.clientY]);
  if (pts.size === 2){                               // pinch zoom
    const [a, b] = [...pts.values()]; const other = a === pts.get(e.pointerId) ? b : a;
    const d0 = Math.hypot(old[0] - other[0], old[1] - other[1]), d1 = Math.hypot(e.clientX - other[0], e.clientY - other[1]);
    if (d0 > 0){ zoomAt((e.clientX + other[0]) / 2, (e.clientY + other[1]) / 2, d1 / d0); } return;
  }
  const dx = e.clientX - old[0], dy = e.clientY - old[1];
  if (Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y) > 4) moved = true;
  if (moved){ setFollow(false); const f = cam.s * base(); cam.x -= dx / f; cam.y -= dy / f; camT.x = cam.x; camT.y = cam.y; camT.s = cam.s; }
});
function endPtr(e){
  pts.delete(e.pointerId); cv.classList.remove("drag");
  if (!moved && e.type === "pointerup") pick(e.clientX, e.clientY);
}
cv.addEventListener("pointerup", endPtr); cv.addEventListener("pointercancel", endPtr);
function zoomAt(px, py, f){
  setFollow(false);
  const bx = wx(px), by = wy(py);
  cam.s = Math.max(0.2, Math.min(60, cam.s * f));
  cam.x = bx - (px - vw / 2) / (cam.s * base()); cam.y = by - (py - vh / 2) / (cam.s * base());
  camT.x = cam.x; camT.y = cam.y; camT.s = cam.s;
}
cv.addEventListener("wheel", e => { e.preventDefault(); zoomAt(e.clientX, e.clientY, Math.exp(-e.deltaY * 0.0015)); }, {passive: false});

function pick(px, py){
  const doneN = Math.max(0, Math.min(S.length, Math.floor((t - 1) * W) + 1));
  let best = -1, bd = 14 * 14;
  for (let i = 0; i < doneN; i++){ const n = S[i][0]; const dx = sx(X[n]) - px, dy = sy(Y[n]) - py, d = dx*dx + dy*dy; if (d < bd){ bd = d; best = n; } }
  selected = best;
  if (best < 0){ $("info").style.display = "none"; return; }
  const nd = D.nodes[best], st = S[rank[best]];
  $("iT").textContent = nd[3];
  const tab = $("iTab"); tab.textContent = "";
  const rows = [["kind", D.kinds[nd[2]]], ["discovered", "step " + (rank[best] + 1) + " of " + S.length],
                ["via", st[1] >= 0 ? (st[4] ? D.nodes[st[1]][3] + " —" + D.rels[st[2]] + "→ this"
                                       : "this —" + D.rels[st[2]] + "→ " + D.nodes[st[1]][3] + " (walked backwards)")
                                : "root (crawl start)"], ["depth", st[3]]];
  for (const k in nd[4]) rows.push([k, nd[4][k]]);
  for (const [a, b] of rows){ const tr = document.createElement("tr"); const c1 = document.createElement("td"), c2 = document.createElement("td");
    c1.textContent = a; c2.textContent = String(b); tr.appendChild(c1); tr.appendChild(c2); tab.appendChild(tr); }
  $("info").style.display = "block";
}

/* ---- go ---- */
setMode(mode);
playing = !reduce && N > 0;
requestAnimationFrame(loop);
</script>
</body>
</html>
"""


# ============================================================================
#  Tkinter GUI
# ============================================================================

class NeuralSchemaGUI:
    def __init__(self, initial_graph=None):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
        import matplotlib
        matplotlib.use("TkAgg")
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import (
            FigureCanvasTkAgg, NavigationToolbar2Tk)

        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox

        self.root = tk.Tk()
        self.root.title("NeuralSchema — Universal Code & System Architecture Analyzer")
        self.root.geometry("1360x860")
        self.root.minsize(1040, 640)
        self.root.configure(bg="#161b22")

        self._init_style()

        self.graph = initial_graph
        self.pos = None
        self.highlight = set()
        self.scatter = None
        self.node_order = []
        self.path = tk.StringVar(value="")
        self.mode = tk.StringVar(value="code")
        self.layout_algo = tk.StringVar(value="spring")
        self.top_n = tk.IntVar(value=40)
        self.show_ext = tk.BooleanVar(value=True)
        self.show_conns = tk.BooleanVar(value=False)
        self.sast = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Ready.  Pick a mode, then Analyze.")

        import queue
        self._work_q = queue.Queue()
        self._busy = False

        self._build_controls()
        self._build_body(Figure, FigureCanvasTkAgg, NavigationToolbar2Tk)
        self._build_statusbar()

        if self.graph is not None:
            self._render_graph()

    # -- theming ------------------------------------------------------------
    def _init_style(self):
        s = self.ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        bg, panel, fg, acc = "#161b22", "#0d1117", "#c9d1d9", "#1f6feb"
        s.configure(".", background=bg, foreground=fg, fieldbackground=panel,
                    bordercolor="#30363d")
        s.configure("TFrame", background=bg)
        s.configure("TLabel", background=bg, foreground=fg)
        s.configure("TButton", background="#21262d", foreground=fg, padding=5)
        s.map("TButton", background=[("active", acc)])
        s.configure("Accent.TButton", background=acc, foreground="#ffffff",
                    padding=6, font=("", 10, "bold"))
        s.map("Accent.TButton", background=[("active", "#388bfd")])
        s.configure("TRadiobutton", background=bg, foreground=fg)
        s.configure("TCheckbutton", background=bg, foreground=fg)
        s.configure("Treeview", background=panel, fieldbackground=panel,
                    foreground=fg, rowheight=22, borderwidth=0)
        s.configure("Treeview.Heading", background="#21262d", foreground=fg)
        s.map("Treeview", background=[("selected", acc)])
        s.configure("TCombobox", fieldbackground=panel, foreground=fg)
        s.configure("TSpinbox", fieldbackground=panel, foreground=fg)

    # -- controls bar -------------------------------------------------------
    def _build_controls(self):
        ttk, tk = self.ttk, self.tk
        bar = ttk.Frame(self.root, padding=(10, 8))
        bar.pack(side="top", fill="x")

        ttk.Label(bar, text="Mode:").pack(side="left")
        ttk.Radiobutton(bar, text="Code", variable=self.mode, value="code",
                        command=self._on_mode).pack(side="left", padx=(4, 0))
        ttk.Radiobutton(bar, text="System (OS)", variable=self.mode,
                        value="system", command=self._on_mode).pack(side="left")

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=10)

        self.btn_file = ttk.Button(bar, text="Open File…", command=self._open_file)
        self.btn_file.pack(side="left")
        self.btn_dir = ttk.Button(bar, text="Open Folder…", command=self._open_dir)
        self.btn_dir.pack(side="left", padx=(4, 0))
        self.path_lbl = ttk.Label(bar, textvariable=self.path, width=34)
        self.path_lbl.pack(side="left", padx=8)

        self.btn_analyze = ttk.Button(bar, text="Analyze ▶", style="Accent.TButton",
                                      command=self._analyze)
        self.btn_analyze.pack(side="left", padx=(4, 0))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=10)

        # options
        self.opts = ttk.Frame(bar)
        self.opts.pack(side="left")
        ttk.Label(self.opts, text="Top procs:").pack(side="left")
        ttk.Spinbox(self.opts, from_=5, to=200, width=5, textvariable=self.top_n
                    ).pack(side="left", padx=(2, 8))
        ttk.Checkbutton(self.opts, text="SAST", variable=self.sast
                        ).pack(side="left")
        ttk.Checkbutton(self.opts, text="Ext calls", variable=self.show_ext
                        ).pack(side="left", padx=(6, 0))
        ttk.Checkbutton(self.opts, text="Ports/conns", variable=self.show_conns
                        ).pack(side="left", padx=(6, 0))

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(bar, text="Layout:").pack(side="left")
        ttk.Combobox(bar, textvariable=self.layout_algo, width=9, state="readonly",
                     values=["spring", "kamada", "shell", "circular"]
                     ).pack(side="left", padx=(2, 6))
        ttk.Button(bar, text="Re-layout", command=self._relayout).pack(side="left")

        # exports on the right
        # Crawl Mode: writes the animated crawler page and opens it in the
        # default browser so the user sees the animation immediately.
        ttk.Button(bar, text="Crawl ▶", style="Accent.TButton",
                   command=lambda: self._export("crawl")).pack(side="right")
        ttk.Button(bar, text="Export HTML", command=lambda: self._export("html")
                   ).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Export PNG", command=lambda: self._export("png")
                   ).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Export JSON", command=lambda: self._export("json")
                   ).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="📋 Report", style="Accent.TButton",
                   command=self._show_report).pack(side="right", padx=(0, 6))
        self._on_mode()

    # -- body: side panel + canvas -----------------------------------------
    def _build_body(self, Figure, FigureCanvasTkAgg, NavigationToolbar2Tk):
        ttk, tk = self.ttk, self.tk
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(side="top", fill="both", expand=True, padx=8, pady=(0, 6))

        # left panel
        left = ttk.Frame(paned, width=330)
        paned.add(left, weight=0)
        ttk.Label(left, text="Entities", font=("", 10, "bold")).pack(
            anchor="w", pady=(4, 2))
        self.tree = ttk.Treeview(left, show="tree", selectmode="browse", height=20)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        ttk.Label(left, text="Details", font=("", 10, "bold")).pack(
            anchor="w", pady=(8, 2))
        self.detail = tk.Text(left, height=10, bg="#0d1117", fg="#c9d1d9",
                              insertbackground="#c9d1d9", relief="flat",
                              wrap="word", font=("TkFixedFont", 9))
        self.detail.pack(fill="x")
        self.detail.configure(state="disabled")

        # right: matplotlib canvas + toolbar
        right = ttk.Frame(paned)
        paned.add(right, weight=1)
        self.fig = Figure(figsize=(9, 7), facecolor="#0d1117")
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor("#0d1117")
        self.ax.set_xticks([]); self.ax.set_yticks([])
        self.canvas = FigureCanvasTkAgg(self.fig, master=right)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        toolbar = NavigationToolbar2Tk(self.canvas, right, pack_toolbar=False)
        toolbar.update()
        toolbar.pack(side="bottom", fill="x")
        try:
            toolbar.configure(background="#161b22")
        except Exception:
            pass
        self.canvas.mpl_connect("pick_event", self._on_pick)

    def _build_statusbar(self):
        ttk = self.ttk
        sb = ttk.Frame(self.root, padding=(10, 4))
        sb.pack(side="bottom", fill="x")
        ttk.Label(sb, textvariable=self.status).pack(side="left")
        self.counts_lbl = ttk.Label(sb, text="")
        self.counts_lbl.pack(side="right")

    # -- control callbacks --------------------------------------------------
    def _on_mode(self):
        code = self.mode.get() == "code"
        state = "normal" if code else "disabled"
        self.btn_file.configure(state=state)
        self.btn_dir.configure(state=state)
        if code:
            self.status.set("Code mode — open a file or folder, then Analyze.")
        else:
            self.status.set("System mode — press Analyze to scan this machine.")

    def _open_file(self):
        p = self.filedialog.askopenfilename(
            title="Choose a source file",
            filetypes=[("Source", "*.py *.c *.h *.cpp *.cc *.hpp *.java *.cs *.sh *.bash"),
                       ("All files", "*.*")])
        if p:
            self.path.set(p)

    def _open_dir(self):
        p = self.filedialog.askdirectory(title="Choose a project folder")
        if p:
            self.path.set(p)

    def _analyze(self):
        if self._busy:
            return
        try:
            if self.mode.get() == "system":
                # fast enough to run inline
                self.status.set("Scanning system…")
                self.root.update_idletasks()
                sg = SystemAnalyzer(top_processes=self.top_n.get(),
                                    include_connections=self.show_conns.get()
                                    ).analyze()
                self.graph = sg
                self.highlight = set()
                self._render_graph()
                return

            p = self.path.get().strip()
            if not p:
                self.messagebox.showinfo("NeuralSchema", "Open a file or folder first.")
                self.status.set("Ready.")
                return
            if os.path.isfile(p):
                self.status.set("Analyzing…")
                self.root.update_idletasks()
                sg = analyze_file(p, include_external=self.show_ext.get(),
                                  sast=self.sast.get())
                self.graph = sg
                self.highlight = set()
                self._render_graph()
                return

            # directory -> potentially large -> run on a worker thread so the
            # UI stays responsive; progress is streamed back through a queue.
            import threading
            self._busy = True
            self.btn_analyze.configure(state="disabled")
            self.status.set("Scanning project…")
            t = threading.Thread(target=self._worker_dir,
                                 args=(p, self.show_ext.get(), self.sast.get()),
                                 daemon=True)
            t.start()
            self.root.after(100, self._poll_work)
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.messagebox.showerror("Analysis failed", str(e))
            self.status.set("Analysis failed.")

    def _worker_dir(self, path, ext, sast):
        try:
            def prog(done, total, cur):
                self._work_q.put(("progress", done, total, cur))
            sg = analyze_directory(path, include_external=ext, sast=sast,
                                   progress=prog)
            self._work_q.put(("done", sg))
        except Exception as e:
            self._work_q.put(("error", e))

    def _poll_work(self):
        import queue
        try:
            while True:
                msg = self._work_q.get_nowait()
                if msg[0] == "progress":
                    _, done, total, cur = msg
                    self.status.set(
                        f"Scanning {done}/{total} — {os.path.basename(cur)}")
                elif msg[0] == "done":
                    self._busy = False
                    self.btn_analyze.configure(state="normal")
                    self.graph = msg[1]
                    self.highlight = set()
                    self._render_graph()
                    return
                elif msg[0] == "error":
                    self._busy = False
                    self.btn_analyze.configure(state="normal")
                    import traceback
                    traceback.print_exception(type(msg[1]), msg[1],
                                              msg[1].__traceback__)
                    self.messagebox.showerror("Analysis failed", str(msg[1]))
                    self.status.set("Analysis failed.")
                    return
        except queue.Empty:
            pass
        self.root.after(100, self._poll_work)

    def _relayout(self):
        if self.graph is None:
            return
        self.pos = compute_layout(self.graph, self.layout_algo.get())
        self._redraw()

    def _render_graph(self):
        self.pos = compute_layout(self.graph, self.layout_algo.get())
        self._populate_tree()
        self._redraw()
        c = self.graph.to_dict()["meta"]
        self.counts_lbl.configure(
            text=f"{c['node_count']} nodes · {c['edge_count']} edges")
        summary = " · ".join(f"{k}:{v}" for k, v in
                             sorted(self.graph.counts().items()))
        self.status.set(f"{self.graph.title}   [{summary}]")

    def _redraw(self):
        self.scatter, self.node_order = draw_schema(
            self.ax, self.graph, self.pos, highlight=self.highlight)
        t = self.graph.title
        if self.graph.language and self.graph.language != "mixed":
            t += f"  ·  {self.graph.language}"
        self.ax.set_title(t, color="#c9d1d9", fontsize=12, pad=12)
        self.canvas.draw_idle()

    # -- tree ---------------------------------------------------------------
    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        self._iid_to_node = {}
        nodes = self.graph.nodes()
        by_kind = defaultdict(list)
        for nid, attrs in nodes.items():
            by_kind[attrs["kind"]].append((nid, attrs))
        kind_order = list(KIND_COLOR.keys())
        for kind in sorted(by_kind, key=lambda k: kind_order.index(k)
                           if k in kind_order else 999):
            items = sorted(by_kind[kind], key=lambda t: t[1]["label"].lower())
            parent = self.tree.insert("", "end",
                                      text=f"{kind}  ({len(items)})", open=False)
            for nid, attrs in items:
                iid = self.tree.insert(parent, "end", text=attrs["label"])
                self._iid_to_node[iid] = nid

    def _on_tree_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        nid = self._iid_to_node.get(sel[0])
        if nid is None:
            return
        self.highlight = {nid}
        self._show_details(nid)
        self._redraw()

    # -- canvas pick --------------------------------------------------------
    def _on_pick(self, event):
        if event.artist is not self.scatter:
            return
        idx = event.ind
        if idx is None or len(idx) == 0:
            return
        nid = self.node_order[idx[0]]
        self.highlight = {nid}
        self._show_details(nid)
        # reflect selection in tree
        for iid, mapped in getattr(self, "_iid_to_node", {}).items():
            if mapped == nid:
                self.tree.see(iid)
                self.tree.selection_set(iid)
                break
        self._redraw()

    def _show_details(self, nid):
        attrs = self.graph.nodes().get(nid, {})
        neigh = self.graph.neighbors(nid)
        lines = [f"{attrs.get('label','')}", "-" * 30,
                 f"kind      : {attrs.get('kind','')}"]
        for k, v in attrs.items():
            if k in ("kind", "label"):
                continue
            lines.append(f"{k:<10}: {v}")
        lines.append(f"neighbours: {len(neigh)}")
        # list a few edges
        outs = [(d, r) for (s, d, r) in self.graph.edges() if s == nid][:12]
        ins = [(s, r) for (s, d, r) in self.graph.edges() if d == nid][:12]
        if outs:
            lines.append("")
            lines.append("→ out:")
            for d, r in outs:
                lines.append(f"   {r}: {self.graph.nodes()[d]['label']}")
        if ins:
            lines.append("← in:")
            for s, r in ins:
                lines.append(f"   {r}: {self.graph.nodes()[s]['label']}")
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", "\n".join(lines))
        self.detail.configure(state="disabled")

    # -- export -------------------------------------------------------------
    def _export(self, fmt):
        if self.graph is None:
            self.messagebox.showinfo("NeuralSchema", "Nothing to export — analyze first.")
            return
        ext = {"json": ".json", "png": ".png", "html": ".html",
               "report": ".md", "crawl": ".html"}[fmt]
        suffix = ".crawl" if fmt == "crawl" else ""
        default = f"{_safe_name(self.graph.title)}{suffix}{ext}"
        p = self.filedialog.asksaveasfilename(defaultextension=ext,
                                              initialfile=default)
        if not p:
            return
        try:
            if fmt == "crawl":
                export_crawl(self.graph, p, algo=self.layout_algo.get())
                import webbrowser
                webbrowser.open("file://" + os.path.abspath(p))
            elif fmt == "json":
                export_json(self.graph, p)
            elif fmt == "png":
                export_png(self.graph, p, self.layout_algo.get())
            elif fmt == "report":
                export_report(self.graph, p)
            else:
                export_html(self.graph, p, self.layout_algo.get())
            self.status.set(f"Exported: {p}")
        except Exception as e:
            self.messagebox.showerror("Export failed", str(e))

    def _show_report(self):
        """Open a window with the static-analysis report; offer to save as .md."""
        if self.graph is None:
            self.messagebox.showinfo("NeuralSchema", "Analyze something first.")
            return
        tk = self.tk
        try:
            text = report_to_text(build_report(self.graph))
        except Exception as e:
            self.messagebox.showerror("Report failed", str(e))
            return
        win = tk.Toplevel(self.root)
        win.title(f"Static Analysis Report — {self.graph.title}")
        win.geometry("760x620")
        win.configure(bg="#0d1117")
        txt = tk.Text(win, bg="#0d1117", fg="#c9d1d9", insertbackground="#c9d1d9",
                      relief="flat", wrap="none", font=("TkFixedFont", 10),
                      padx=12, pady=10)
        yscroll = self.ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        txt.pack(side="top", fill="both", expand=True)
        # simple colour cues for severity words
        txt.tag_configure("hi", foreground="#ff3860")
        txt.tag_configure("hdr", foreground="#58a6ff")
        txt.insert("1.0", text)
        txt.configure(state="disabled")
        btnbar = self.ttk.Frame(win)
        btnbar.pack(side="bottom", fill="x")
        self.ttk.Button(btnbar, text="Save as Markdown (.md)",
                        command=lambda: self._export("report")).pack(
            side="right", padx=8, pady=6)

    def run(self):
        self.root.mainloop()


def _safe_name(s):
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:60]


# ============================================================================
#  Command line entry point
# ============================================================================

def build_from_args(args):
    # --url: crawl a website (Crawl Mode).  Checked first because it is the
    # most specific source; the result is an ordinary SchemaGraph, so every
    # export below works on it.
    if getattr(args, "url", None):
        def prog(done, total, url):
            print(f"\r  crawled {done}/{total}  {url[:70]:70}", end="", flush=True)
        crawler = WebCrawler(max_pages=args.max_pages,
                             same_domain=not args.all_domains,
                             delay=args.crawl_delay,
                             strategy=args.strategy if args.strategy != "replay" else "bfs")
        sg = crawler.crawl(args.url, progress=prog)
        print()
        return sg
    if args.system:
        return SystemAnalyzer(top_processes=args.top,
                              include_connections=args.connections).analyze()
    if args.file:
        p = args.file
        sast = not args.no_sast
        if os.path.isdir(p):
            def prog(done, total, cur):
                print(f"\r  scanning {done}/{total}", end="", flush=True)
            sg = analyze_directory(p, include_external=not args.no_external,
                                   sast=sast, progress=prog)
            print()
            return sg
        return analyze_file(p, include_external=not args.no_external, sast=sast)
    return None


def _print_security_summary(sg):
    """Print any SAST findings and privileged/exposed system nodes."""
    nodes = sg.nodes()
    vulns = [(a.get("severity", "?"), a["label"], a.get("line"))
             for a in nodes.values() if a["kind"] == K_VULN]
    ports = [a["label"] for a in nodes.values() if a["kind"] == K_PORT]
    roots = [a["label"] for a in nodes.values()
             if a["kind"] == K_PROCESS and a.get("privileged")]
    if vulns:
        hi = sum(1 for v in vulns if v[0] == "high")
        med = sum(1 for v in vulns if v[0] == "medium")
        print(f"\n[SAST] {len(vulns)} flagged call(s)  "
              f"({hi} high, {med} medium) — heuristic, verify manually:")
        for sev, label, line in sorted(vulns, key=lambda t: t[0]):
            loc = f" (line {line})" if line else ""
            print(f"   {sev:6} {label}{loc}")
    if ports:
        print(f"\n[PORTS] {len(ports)} listening socket(s): "
              + ", ".join(sorted(set(ports))[:20]))
    if roots:
        print(f"\n[PRIV] {len(roots)} root/SYSTEM process(es) shown.")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="NeuralSchema — universal code & system architecture analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", "-f", help="source file OR project directory to analyze")
    ap.add_argument("--system", "-s", action="store_true",
                    help="analyze the live operating system instead")
    ap.add_argument("--top", type=int, default=40,
                    help="system mode: number of heaviest processes (default 40)")
    ap.add_argument("--connections", action="store_true",
                    help="system mode: include network-connection nodes")
    ap.add_argument("--no-external", action="store_true",
                    help="code mode: hide external/undefined call nodes")
    ap.add_argument("--no-sast", action="store_true",
                    help="code mode: disable the dangerous-call (SAST) tagging")
    # --- Crawl Mode options ---
    ap.add_argument("--url", "-u",
                    help="crawl a website starting at this URL (polite: obeys "
                    "robots.txt, waits between requests)")
    ap.add_argument("--max-pages", type=int, default=40,
                    help="url mode: maximum pages to fetch (default 40)")
    ap.add_argument("--crawl-delay", type=float, default=1.0,
                    help="url mode: seconds between requests to one host "
                    "(default 1.0; robots.txt Crawl-delay wins if larger)")
    ap.add_argument("--all-domains", action="store_true",
                    help="url mode: also follow links to other hosts")
    ap.add_argument("--strategy", choices=["bfs", "dfs", "replay"],
                    default="bfs",
                    help="crawl order: bfs (wide), dfs (deep) or replay "
                    "(the real web-crawl order); used by --export crawl")
    ap.add_argument("--logo", help="SVG watermark for the crawl page "
                    "(default: logo-mark.svg next to the script / in cwd)")
    ap.add_argument("--export", "-e", nargs="+",
                    choices=["json", "html", "png", "report", "crawl"],
                    default=[], help="export formats to write "
                    "(report = Markdown static-analysis report, "
                    "crawl = animated crawler page)")
    ap.add_argument("--report", "-r", action="store_true",
                    help="print the static-analysis report to the console")
    ap.add_argument("--out", "-o", default=".",
                    help="output directory / base name for exports (default: .)")
    ap.add_argument("--no-gui", action="store_true",
                    help="do not launch the GUI (useful with --export)")
    args = ap.parse_args(argv)

    # dependencies note: graph layouts and cycle analysis benefit from networkx
    if nx is None:
        pass

    graph = None
    if args.file or args.system or args.url:
        try:
            graph = build_from_args(args)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    # exports
    if graph is not None and args.export:
        out = args.out
        if os.path.isdir(out) or out.endswith("/"):
            os.makedirs(out, exist_ok=True)
            base = os.path.join(out, _safe_name(graph.title))
        else:
            os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
            base = out
        for fmt in args.export:
            ext = {"report": "md", "crawl": "crawl.html"}.get(fmt, fmt)
            path = f"{base}.{ext}"
            try:
                if fmt == "crawl":
                    export_crawl(graph, path, strategy=args.strategy,
                                 logo_path=args.logo)
                elif fmt == "json":
                    export_json(graph, path)
                elif fmt == "png":
                    export_png(graph, path)
                elif fmt == "html":
                    export_html(graph, path)
                elif fmt == "report":
                    export_report(graph, path)
                print(f"wrote {path}")
            except Exception as e:
                print(f"failed to write {fmt}: {e}", file=sys.stderr)

    # schema + report/security summary (whenever a CLI analysis ran)
    if graph is not None and (args.file or args.system or args.url):
        meta = graph.to_dict()["meta"]
        print(f"schema: {meta['node_count']} nodes, {meta['edge_count']} edges, "
              f"kinds={meta['counts_by_kind']}")
        if args.report:
            print("\n" + report_to_text(build_report(graph)))
        else:
            _print_security_summary(graph)

    # GUI
    if not args.no_gui:
        try:
            NeuralSchemaGUI(initial_graph=graph).run()
        except Exception as e:
            print(f"GUI could not start ({e}).", file=sys.stderr)
            if graph is None:
                print("Tip: run headless, e.g.\n"
                      "  python3 neural_schema.py --system --export html --no-gui",
                      file=sys.stderr)
            return 0 if graph is not None else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
