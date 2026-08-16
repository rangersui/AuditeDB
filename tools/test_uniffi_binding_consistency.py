from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from uniffi_binding_consistency import binding_tokens, main


class BindingConsistencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name: str, source: str) -> Path:
        path = self.root / name
        path.write_bytes(source.encode("utf-8"))
        return path

    def run_main(self, tracked: Path, generated: Path) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return main([str(tracked), str(generated)])

    def test_accepts_only_lexically_insignificant_trailing_whitespace(self) -> None:
        tracked = self.write("tracked.py", "value = 1\n# comment\n\n")
        generated = self.write(
            "generated.py",
            "value = 1   \r\n# comment  \r\n    \r\n",
        )

        self.assertEqual(binding_tokens(tracked), binding_tokens(generated))
        self.assertEqual(self.run_main(tracked, generated), 0)

    def test_rejects_changed_runtime_value(self) -> None:
        tracked = self.write("tracked.py", "checksum = 11411\n")
        generated = self.write("generated.py", "checksum = 21227\n")

        self.assertNotEqual(binding_tokens(tracked), binding_tokens(generated))
        self.assertEqual(self.run_main(tracked, generated), 1)

    def test_rejects_changed_docstring_whitespace(self) -> None:
        tracked = self.write("tracked.py", 'class Binding:\n    """current"""\n')
        generated = self.write("generated.py", 'class Binding:\n    """current """\n')

        self.assertNotEqual(binding_tokens(tracked), binding_tokens(generated))
        self.assertEqual(self.run_main(tracked, generated), 1)

    def test_rejects_invalid_line_continuation(self) -> None:
        invalid = self.write("invalid.py", "value = 1 + \\ \n2\n")

        with self.assertRaisesRegex(ValueError, "not valid Python"):
            binding_tokens(invalid)
        self.assertEqual(self.run_main(invalid, invalid), 1)


if __name__ == "__main__":
    unittest.main()
