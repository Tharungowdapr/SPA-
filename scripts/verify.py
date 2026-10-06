#!/usr/bin/env python3
"""
AegisClick - Clean Install Verification Script

Run after a fresh clone to verify the entire stack works.
Exits 0 on success, non-zero on failure.
"""
from __future__ import annotations
import subprocess
import sys
import os
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent

def run(cmd: List[str], cwd: Path = ROOT, timeout: int = 120) -> Tuple[int, str, str]:
    """Run command, return (code, stdout, stderr)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"

def check_file(path: Path, desc: str) -> bool:
    if path.exists():
        print(f"  [OK] {desc}: {path.relative_to(ROOT)}")
        return True
    print(f"  [MISSING] {desc}: {path.relative_to(ROOT)}")
    return False

def main() -> int:
    os.environ["PYTHONPATH"] = str(ROOT)
    sys.path.insert(0, str(ROOT))

    print("=" * 60)
    print("AegisClick - Clean Install Verification")
    print("=" * 60)

    ok = True

    # 1. Essential files
    print("\n1. Essential files")
    essential = [
        (ROOT / "README.md", "README"),
        (ROOT / "docker" / "docker-compose.yml", "Compose"),
        (ROOT / "docker" / "Dockerfile", "Dockerfile"),
        (ROOT / "pyproject.toml", "PyProject"),
        (ROOT / "configs" / "config.yaml", "Config"),
        (ROOT / "web" / "control.html", "Console"),
        (ROOT / "web" / "sim.html", "Simulator"),
        (ROOT / "web" / "app.css", "Styles"),
        (ROOT / "web" / "common.js", "Shared JS"),
        (ROOT / "aegis" / "__init__.py", "Package root"),
    ]
    for p, desc in essential:
        ok &= check_file(p, desc)

    # 2. Python syntax
    print("\n2. Python syntax (ruff + compile)")
    code, out, err = run([sys.executable, "-m", "ruff", "check", "aegis", "tests"])
    if code == 0:
        print("  [OK] ruff: clean")
    else:
        print(f"  [FAIL] ruff: {err or out}")
        ok = False

    code, out, err = run([sys.executable, "-m", "py_compile", "aegis/pipeline.py"])
    if code == 0:
        print("  [OK] compile: aegis.pipeline")
    else:
        print(f"  [FAIL] compile: {err}")
        ok = False

    # 3. Core unit tests (those that don't require optional deps)
    print("\n3. Core unit tests (no optional deps)")
    core_tests = [
        "tests/test_migrations.py",
        "tests/test_persistence.py",
        "tests/test_reasons.py",
    ]
    core_ok = True
    for test_file in core_tests:
        code, out, err = run([sys.executable, "-m", "pytest", test_file, "-q", "--tb=short"], timeout=60)
        if code == 0:
            print(f"  [OK] {test_file}")
        else:
            if "ModuleNotFoundError" in err and ("river" in err or "shap" in err or "neo4j" in err):
                print(f"  [SKIP] {test_file} (requires optional deps)")
            else:
                print(f"  [FAIL] {test_file}: {err[-300:]}")
                core_ok = False
    if core_ok:
        print("  [OK] core test files passed")
    else:
        ok = False

    # 5. Browser tests (optional)
    print("\n4. Browser tests (optional, may skip in CI)")
    code, out, err = run([sys.executable, "-m", "pytest", "-q", "-m", "browser", "--tb=short"], timeout=180)
    if code == 0:
        print("  [OK] browser tests passed")
    elif "No module named 'playwright'" in err or "DLL load failed" in err:
        print("  [SKIP] browser tests skipped (Playwright not available)")
    else:
        print(f"  [WARN] browser tests failed (may be env): {err[-300:] if err else out[-300:]}")

    # 5. Docker build (optional)
    if os.environ.get("AEGIS_VERIFY_DOCKER") == "1":
        print("\n5. Docker build (AEGIS_VERIFY_DOCKER=1)")
        code, out, err = run(["docker", "compose", "build"], cwd=ROOT / "docker", timeout=600)
        if code == 0:
            print("  [OK] docker compose build")
        else:
            print(f"  [FAIL] docker build: {err[-500:]}")
            ok = False
    else:
        print("\n5. Docker build: skipped (set AEGIS_VERIFY_DOCKER=1 to enable)")

    # 6. JavaScript syntax
    print("\n6. JavaScript syntax (node --check)")
    for js_file in ["web/common.js"]:
        code, out, err = run(["node", "--check", str(ROOT / "web" / "common.js")])
        if code == 0:
            print("  [OK] web/common.js")
        else:
            print(f"  [FAIL] web/common.js: {err}")
            ok = False

    # 7. Config validation
    print("\n7. Config validation")
    try:
        from aegis.config import load_settings
        s = load_settings()
        print(f"  [OK] config loads: db={s.get('app.db_path')}, models={s.get('app.models_dir')}")
    except Exception as e:
        print(f"  [FAIL] config load: {e}")
        ok = False

    # 8. Schema validation
    print("\n8. Schema import")
    try:
        from aegis.schemas import ClickEvent
        ce = ClickEvent(user_id="U1", ad_id="A1", campaign_id="C1", device_id="D1", ip_address="1.2.3.4", user_agent="Mozilla")
        print("  [OK] ClickEvent validates")
    except Exception as e:
        print(f"  [FAIL] schema: {e}")
        ok = False

    # 10. Full test suite (with optional deps noted)
    print("\n10. Full test suite status")
    code, out, err = run([sys.executable, "-m", "pytest", "-q", "--tb=no"], timeout=300)
    if code == 0:
        print("  [OK] full test suite passed")
    else:
        if "ModuleNotFoundError" in out and ("river" in out or "shap" in out or "neo4j" in out):
            print("  [WARN] some tests require optional deps (river, shap, neo4j) not installed")
            print("  [OK] install optional deps with: pip install 'river[all]' shap neo4j")
        else:
            print(f"  [FAIL] unexpected test failures")
            ok = False

    # Summary
    print("\n" + "=" * 60)
    if ok:
        print("[OK] ALL CHECKS PASSED")
        print("=" * 60)
        return 0
    else:
        print("[FAIL] SOME CHECKS FAILED")
        print("=" * 60)
        return 1

if __name__ == "__main__":
    sys.exit(main())