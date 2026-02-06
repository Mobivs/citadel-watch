# PRD: Project Setup Configuration
# Reference: docs/PRD.md v0.2.3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="citadel-archer",
    version="0.2.3",
    author="Citadel Archer Team",
    description="AI-centric defensive security platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/citadel-archer",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.109.0",
        "uvicorn[standard]>=0.27.0",
        "watchdog>=3.0.0",
        "psutil>=5.9.7",
        "sqlcipher3>=0.5.2",
        "cryptography>=42.0.0",
        "structlog>=24.1.0",
        # "pywebview>=4.4.1",  # Skip for now - will add when building desktop wrapper
        "httpx>=0.26.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "citadel-archer=citadel_archer.__main__:main",
        ],
    },
)
