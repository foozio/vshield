from setuptools import setup, find_packages

setup(
    name="vshield",
    version="1.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    entry_points={
        "console_scripts": [
            "vshield = vshield.cli:main",
            "vulnshield = vshield.cli:main",
        ],
    },
    python_requires=">=3.9",
)
