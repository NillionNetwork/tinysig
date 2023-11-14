=======
tecdsa
=======

Pure-Python implementation of a `threshold ecdsa signature scheme <https://nillion.pub/sum-of-products-lsss-non-interactive.pdf>`__ based on a secure multi-party computation (MPC) `protocol for evaluating arithmetic sum-of-products expressions <https://nillion.pub/sum-of-products-lsss-non-interactive.pdf>`__ via a non-interactive computation phase.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/tecdsa.svg
   :target: https://badge.fury.io/py/tecdsa
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/tecdsa/badge/?version=latest
   :target: https://tecdsa.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nillion-oss/tecdsa/workflows/lint-test-cover-docs/badge.svg
   :target: https://github.com/nillion-oss/tecdsa/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nillion-oss/tecdsa/badge.svg?branch=main
   :target: https://coveralls.io/github/nillion-oss/tecdsa?branch=main
   :alt: Coveralls test coverage summary.

Installation and Usage
----------------------

This library is available as a `package on PyPI <https://pypi.org/project/tecdsa>`__:

.. code-block:: bash

    python -m pip install tecdsa

The library can be imported in the usual way:

.. code-block:: python

    import tecdsa
    from tecdsa import *

Basic Example
^^^^^^^^^^^^^

This implementation includes the emulation of a network comprised of computing nodes and clients. We can either deploy
a network for DSA or ECDSA. In this example, we will show the Elliptic Curve version with 3 nodes and 1 client with id set to 1.

.. code-block:: python

    >>> N = 3; C = 1; client_id = 1

To kick things off, let's initialize the network using ECDSA with the P-256 curve:

.. code-block:: python

    >>> ecdsa_setup = ECDSASetup(curve="P-256")
    >>> ecnet = ThresholdSignature(N, C, setup=ecdsa_setup)

The first protocol involves distributing a key triple among the nodes:

.. code-block:: python

    >>> ecnet.distributed_key_generation_protocol(client_id)

The signature protocol unfolds in two phases: the preprocessing phase and the signing phase. 
Let's run the preprocessing phase:

.. code-block:: python

    >>> ecnet.ts_prep_protocol(client_id)

After defining a message we can sign it as follows:

.. code-block:: python

    >>> message = "Let me tell you a great secret about Nillion."
    >>> ecnet.ts_online_protocol(message, client_id)

We run the following to print the signature owned by the client (ID=1):

.. code-block:: python

    >>> ecnet.print_signature(client_id)

For a deeper dive, please check the `demos` folder.

Development
-----------
All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__:

.. code-block:: bash

    python -m pip install .[docs,lint]

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    python -m pip install .[docs]
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source ../src && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details):

.. code-block:: bash

    python -m pip install .[test]
    python -m pytest

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install .[lint]
    python -m pylint src/tecdsa

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nillion-oss/tecdsa>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/tecdsa>`__ by a package maintainer. First, install the dependencies required for packaging and publishing:

.. code-block:: bash

    python -m pip install .[publish]

Ensure that the correct version number appears in ``pyproject.toml``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions. Create and push a tag for this version (replacing ``?.?.?`` with the version number):

.. code-block:: bash

    git tag ?.?.?
    git push origin ?.?.?

Remove any old build/distribution files. Then, package the source into a distribution archive:

.. code-block:: bash

    rm -rf build dist src/*.egg-info
    python -m build --sdist --wheel .

Finally, upload the package distribution archive to `PyPI <https://pypi.org>`__:

.. code-block:: bash

    python -m twine upload dist/*
