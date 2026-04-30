"""Build hook for platform wheels.

The elastik Python package ships a native `elastik-core` binary as package
data. That means the wheel is not universal even though the Python code is
stdlib-only. Mark bdist_wheel as non-pure so each runner produces a platform
tag such as `win_amd64`, `macosx_...`, or `linux_x86_64` instead of the
misleading `py3-none-any`.
"""

from __future__ import annotations

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self) -> tuple[str, str, str]:
        _python, _abi, platform = super().get_tag()
        return "py3", "none", platform


setup(cmdclass={"bdist_wheel": bdist_wheel})
