import json
import re
import sys
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

import nids_mvp


class ProjectBootstrapTest(unittest.TestCase):
    def test_python_package_version(self) -> None:
        self.assertEqual(nids_mvp.__version__, "0.1.0")

    def test_cmake_exposes_core_and_optional_toolchain_smoke(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertRegex(cmake, re.compile(r"add_library\s*\(\s*nids_core\b", re.IGNORECASE))
        self.assertRegex(
            cmake,
            re.compile(r"option\s*\(\s*NIDS_BUILD_TOOLCHAIN_SMOKE\b", re.IGNORECASE),
        )
        self.assertRegex(
            cmake,
            re.compile(r"(?:cxx_std_20\b|CMAKE_CXX_STANDARD\s+20\b)", re.IGNORECASE),
        )

    def test_cmake_presets_cover_clean_build_and_test(self) -> None:
        presets = json.loads((ROOT / "CMakePresets.json").read_text(encoding="utf-8"))
        configure = {preset["name"] for preset in presets.get("configurePresets", [])}
        build = {preset["name"] for preset in presets.get("buildPresets", [])}
        test = {preset["name"] for preset in presets.get("testPresets", [])}

        self.assertIn("ubuntu-release", configure)
        self.assertIn("ubuntu-release", build)
        self.assertIn("ubuntu-release", test)

    def test_pyproject_locks_bootstrap_metadata(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = pyproject["project"]

        self.assertEqual(project["version"], "0.1.0")
        self.assertEqual(project["requires-python"], ">=3.12")


if __name__ == "__main__":
    unittest.main()
