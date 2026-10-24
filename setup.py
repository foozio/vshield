from setuptools import setup, find_packages

setup(
    name="vulnshield",
    version="1.1.0",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    entry_points={
        "console_scripts": [
            "vulnshield = vulnshield.cli:main",
        ],
    },
    python_requires=">=3.9",
)
