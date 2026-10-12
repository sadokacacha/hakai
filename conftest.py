"""Pytest bootstrap: put the project root on sys.path so `import core`, etc. work."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
