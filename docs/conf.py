import os
import sys
sys.path.insert(0, os.path.abspath(".."))

project = "HW2 Code Documentation"
author = "Siddhi Pandkar"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "alabaster"
latex_engine = "pdflatex"
