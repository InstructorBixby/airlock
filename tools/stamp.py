"""Write the commit into the package, just before it is built.

Only the tag pipeline runs this. An install out of a working tree has
no `_build.py` and `airlock --version` says `(checkout)` rather than
claiming a commit it cannot know, because "which build is serving"
has to have a true answer and a confident wrong one is worse than
none.
"""
from __future__ import annotations

import os
import pathlib

sha = os.environ["CI_COMMIT_SHA"]
pathlib.Path("airlock/_build.py").write_text(
    "# Written by the tag pipeline. Absent in a checkout install.\n"
    f'COMMIT = "{sha}"\n')
