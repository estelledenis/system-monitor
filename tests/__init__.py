# tests/__init__.py

import os
import sys

def setup_test_environment():
    """Ensure the project root is in sys.path during tests."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

