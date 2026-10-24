import warnings
from vshield.cli import *  # noqa: F401, F403
from vshield.cli import main

warnings.warn(
    "The 'vulnshield.cli' module has been renamed to 'vshield.cli'.",
    DeprecationWarning,
    stacklevel=2,
)

if __name__ == "__main__":
    main()
