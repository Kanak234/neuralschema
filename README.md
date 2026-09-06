# NeuralSchema

Universal Code & System Architecture Analyzer.

Builds a "neural schema" (an architecture graph of nodes + relations) for:

1. **Source code** across many languages
   - Python (`.py`) — via the built-in `ast` module
   - C (`.c` `.h`) — via tree-sitter
   - C++ (`.cpp` `.hpp` ..) — via tree-sitter
   - Java (`.java`) — via tree-sitter
   - C# (`.cs`) — via tree-sitter
   - Shell (`.sh` `.bash`) — via tree-sitter (Bash / sh)

   Extracts modules, namespaces, classes/structs/interfaces, functions,
   methods, imports/includes, inheritance, and call-graph edges — for shell,
   also the external programs a script invokes.

2. **The operating system itself** (live introspection via `psutil`)
   - CPU / memory / disks / network interfaces / logged-in users and a
     process tree (parent → child) of the heaviest processes, with optional
     network-connection nodes.

The result can be:
- explored interactively in a Tkinter GUI (force-directed graph, click a node
  to inspect it and highlight its neighbours),
- exported to a self-contained interactive HTML page (works offline),
- exported to JSON (nodes + edges), or a PNG snapshot.

## Usage

```bash
# Launch the GUI (default when no analysis flags are given):
python3 neural_schema.py

# Command line -- analyse a file, a whole project folder, or the OS:
python3 neural_schema.py --file path/to/program.py
python3 neural_schema.py --file path/to/project_dir
python3 neural_schema.py --system --top 50

# Add exports (any combination), optionally with --no-gui to stay headless:
python3 neural_schema.py --file src/ --export html json png --out ./schema --no-gui
python3 neural_schema.py --system --connections --export html --no-gui
```

## Dependencies

```bash
pip install psutil networkx matplotlib tree-sitter tree-sitter-language-pack pyvis
```

Single-file, no build step.
