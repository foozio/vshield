"""Backward-compatibility shim for legacy 'vulnshield' imports."""

import warnings
import vshield
from vshield import *  # noqa: F401, F403

warnings.warn(
    "The 'vulnshield' module has been renamed to 'vshield'. "
    "Please update your imports. Support for 'vulnshield' is deprecated and will be removed in v2.0.",
    DeprecationWarning,
    stacklevel=2,
)

__version__ = vshield.__version__
