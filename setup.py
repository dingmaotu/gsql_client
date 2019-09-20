import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gsql_client",
    version="0.1.1",
    author="Ding Li",
    author_email="dingmaotu@hotmail.com",
    description="GSQL and RESTPP Python remote clients for TigerGraph",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=['tigergraph', 'gsql', 'restpp', 'client'],
    requires=[],
    url="https://github.com/dingmaotu/gsql_client",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Database :: Front-Ends",
    ],
    python_requires='>=2.7'
)