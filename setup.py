# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

from setuptools import Extension, setup
from setuptools.command.sdist import sdist as SetuptoolsSdist


class sdist_cythonize(SetuptoolsSdist):
    """
    Make sure we always generate a new wireguard_py.c when we build a source
    distribution; this ensures we never ship a stale version and that users
    won't need the cython module installed in order to build the package.
    """

    def run(self, *args, **kwargs):
        from Cython.Build import cythonize

        cythonize(["wireguard_py/wireguard_py.pyx"])
        super().run(*args, **kwargs)


extensions = [
    Extension(
        name="wireguard_py.wireguard_py",
        sources=[
            "wireguard_py/wireguard_py.c",
            "wireguard_py/wireguard_tools/wireguard.c",
        ],
        depends=["wireguard_py/wireguard_tools/wireguard.h"],
        include_dirs=["."],
        library_dirs=["/usr/lib"],
        libraries=["rt"],
    )
]

setup(
    packages=["wireguard_py"],
    cmdclass={"sdist": sdist_cythonize},
    include_package_data=False,
    ext_modules=extensions,
    entry_points={
        "console_scripts": [
            "wgpy = wireguard_py.wgpy:cli",
        ],
    },
)
