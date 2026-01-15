# Class Diagram Generation - Reference

Reference guide for developers working with automatic class diagram generation.

---

## Quick Commands

### Build Documentation
```bash
cd docs
sphinx-build -b html . _build/html
```

### Clean Build (Force Regeneration)
```bash
cd docs
rm -rf _build
sphinx-build -b html . _build/html
```

### View Documentation
```bash
# Windows
start docs\_build\html\index.html

# macOS
open docs/_build/html/index.html

# Linux
xdg-open docs/_build/html/index.html
```

---

## One-Time Setup

### Install Graphviz

**Windows:**
```powershell
# Download from https://graphviz.org/download/
# Run installer, add to PATH
dot -V  # Verify
```

**macOS:**
```bash
brew install graphviz
dot -V
```

**Linux:**
```bash
sudo apt-get install -y graphviz  # Ubuntu/Debian
sudo dnf install graphviz         # Fedora/RHEL
dot -V
```

### Install Python Dependencies
```bash
pip install -r dev-requirements.txt
```

---

## Add New Diagram

### Inheritance Diagram (Auto-generated from code)

Edit `docs/class_diagrams.rst`:

```rst
My Module Classes
-----------------

.. inheritance-diagram:: cryptnox_sdk_py.mymodule
   :parts: 1
   :caption: My module hierarchy
```

### Custom Diagram (Manual Graphviz)

Edit `docs/class_diagrams.rst`:

```rst
My Architecture
---------------

.. graphviz::
   :caption: System architecture

   digraph {
      rankdir=LR;
      node [shape=box, style="rounded,filled", fillcolor=lightblue];
      
      App -> API -> Database;
   }
```

---

## Common Customizations

### Change Layout Direction

```rst
.. graphviz::
   digraph {
      rankdir=LR;  # Left to Right (horizontal)
      # rankdir=TB;  # Top to Bottom (vertical)
   }
```

### Change Colors

```python
fillcolor=lightblue   # Blue
fillcolor=lightgreen  # Green
fillcolor=lightyellow # Yellow
fillcolor=lightcoral  # Red
fillcolor=lightgray   # Gray
```

### Change Size

Edit `docs/conf.py`:
```python
inheritance_graph_attrs = {
    'size': '"12.0, 8.0"',  # width, height in inches
}
```

---

## Quick Troubleshooting

### "dot command not found"
```bash
# Install Graphviz, then restart terminal
dot -V  # Should show version
```

### Diagrams not updating
```bash
# Force clean rebuild
cd docs && rm -rf _build && sphinx-build -b html . _build/html
```

### Import errors
Add to `docs/conf.py`:
```python
autodoc_mock_imports = [
    'your_external_package',
]
```

### Diagrams not visible in browser
```bash
# Hard refresh browser
Ctrl + Shift + R  # or Ctrl + F5
```

---

## Key Files

| File | Purpose |
|------|---------|
| `docs/class_diagrams.rst` | Define diagrams here |
| `docs/conf.py` | Sphinx & diagram configuration |
| `dev-requirements.txt` | Python dependencies |
| `.github/workflows/docs.yml` | GitHub Actions workflow |

---

## Verification Checklist

Before committing:

- [ ] `sphinx-build` completes with 0 errors
- [ ] SVG files in `docs/_build/html/_images/`
- [ ] Diagrams visible in browser
- [ ] Tested clean build
