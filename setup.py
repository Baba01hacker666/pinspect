from setuptools import setup, find_packages

setup(
    name="pinspect-cli",
    version="1.0.2",
    description="Fast Linux process-intelligence CLI and forensics tool that goes far beyond ps aux",
    author="Baba01hacker666",
    packages=find_packages(include=["pinspect", "pinspect.*"]),
    install_requires=[
        "rich>=12.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pinspect = pinspect.cli.main:main",
        ],
    },
    keywords=[
        "linux",
        "procfs",
        "process",
        "cli",
        "security",
        "forensics",
        "tui",
        "edr",
        "siem",
        "system-monitoring",
        "process-intelligence",
        "process-tree",
        "systemd",
        "cgroups",
        "namespaces",
        "capabilities",
        "pstree",
        "lsof",
        "terminal-ui",
    ],
    python_requires=">=3.8",
)
