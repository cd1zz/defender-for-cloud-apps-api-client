"""Setup script for Microsoft Defender for Cloud Apps API Client."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8") if (this_directory / "README.md").exists() else ""

setup(
    name="defender-cloud-apps-api-client",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Python client for Microsoft Defender for Cloud Apps API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/defender-for-cloud-apps-api-client",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "types-requests>=2.31.0",
        ],
    },
    keywords="microsoft defender cloud apps security api mdca casb",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/defender-for-cloud-apps-api-client/issues",
        "Source": "https://github.com/yourusername/defender-for-cloud-apps-api-client",
        "Documentation": "https://learn.microsoft.com/en-us/defender-cloud-apps/api-introduction",
    },
)
