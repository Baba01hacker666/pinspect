from setuptools import setup, find_packages

setup(
    name="pinspect-cli",
    version="1.0.0",
    description="Fast Linux process-intelligence CLI tool that goes far beyond ps aux",
    author="Antigravity",
    packages=find_packages(include=["pinspect", "pinspect.*"]),
    install_requires=[
        "rich>=12.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pinspect = pinspect.cli.main:main",
        ],
    },
    python_requires=">=3.8",
)
