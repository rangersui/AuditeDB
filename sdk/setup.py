"""Build hook for platform wheels.

The elastik Python package ships a native `elastik-core` binary as package
data. That means the wheel is not universal even though the Python code is
stdlib-only. Mark bdist_wheel as non-pure so each runner produces a platform
tag such as `win_amd64`, `macosx_...`, or `linux_x86_64` instead of the
misleading `py3-none-any`.
"""

from __future__ import annotations

import os

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
from setuptools.command.install import install as _install


class install(_install):
    def finalize_options(self) -> None:
        super().finalize_options()
        # auditwheel only repairs wheels whose native binaries live in platlib.
        # root_is_pure=False fixes the tag; this fixes the install scheme.
        self.install_lib = self.install_platlib


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self) -> tuple[str, str, str]:
        _python, _abi, platform = super().get_tag()
        platform = os.environ.get("ELASTIK_WHEEL_PLATFORM_TAG") or platform
        return "py3", "none", platform


setup(cmdclass={"bdist_wheel": bdist_wheel, "install": install})
