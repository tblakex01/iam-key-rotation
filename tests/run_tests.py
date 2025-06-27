#!/usr/bin/env python3
"""
Test runner for AWS IAM Key Rotation project
Runs all tests and generates a comprehensive report
"""

import sys
import unittest
import re
from pathlib import Path


def run_tests():
    """Run all tests and generate report"""
    print("🔍 Running AWS IAM Key Rotation Test Suite")
    print("=" * 50)

    # Get the tests directory
    tests_dir = Path(__file__).parent

    # Discover and run all tests
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(tests_dir), pattern="test_*.py")

    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2, stream=sys.stdout, descriptions=True, failfast=False
    )

    print(f"\n📋 Discovered {suite.countTestCases()} test cases")
    print("-" * 50)

    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)

    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped) if hasattr(result, "skipped") else 0
    passed = total_tests - failures - errors - skipped

    print(f"Total Tests:  {total_tests}")
    print(f"✅ Passed:    {passed}")
    print(f"❌ Failed:    {failures}")
    print(f"💥 Errors:    {errors}")
    print(f"⏭️  Skipped:   {skipped}")

    if result.wasSuccessful():
        print(f"\n🎉 ALL TESTS PASSED! ({passed}/{total_tests})")
        success_rate = 100.0
    else:
        success_rate = (passed / total_tests) * 100 if total_tests > 0 else 0
        print(f"\n⚠️  TESTS FAILED! Success rate: {success_rate:.1f}%")

    # Print detailed failure information
    if failures:
        print("\n" + "=" * 50)
        print("💔 FAILURE DETAILS")
        print("=" * 50)
        for test, traceback in result.failures:
            print(f"\n❌ {test}")
            print("-" * 30)
            print(traceback)

    if errors:
        print("\n" + "=" * 50)
        print("💥 ERROR DETAILS")
        print("=" * 50)
        for test, traceback in result.errors:
            print(f"\n💥 {test}")
            print("-" * 30)
            print(traceback)

    return result.wasSuccessful()


def check_dependencies():
    """Check if all required test dependencies are installed"""
    required_packages = ["boto3", "botocore", "rich", "python-dateutil"]

    missing_packages = []

    for package in required_packages:
        try:
            if package == "python-dateutil":
                __import__("dateutil")
            else:
                __import__(package.replace("-", "_"))
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\nInstall missing packages with:")
        print("   pip install " + " ".join(missing_packages))
        return False

    return True


def run_security_checks():
    """Run basic security checks on the codebase"""
    print("\n🔒 Running Security Checks")
    print("-" * 30)

    # Check for hardcoded secrets
    secrets_found = False

    # Get project root
    project_root = Path(__file__).parent.parent

    # Patterns to look for (more specific to reduce false positives)
    secret_patterns = [
        r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID pattern
        r"['\"][A-Za-z0-9/+=]{40}['\"]",  # AWS Secret Access Key pattern
        r"password\s*=\s*['\"][^'\"]+['\"]",  # password assignment
        r"token\s*=\s*['\"][^'\"]+['\"]",  # token assignment
    ]

    python_files = list(project_root.rglob("*.py"))

    for file_path in python_files:
        if (
            "test" in file_path.name
            or "__pycache__" in str(file_path)
            or "venv" in str(file_path)
            or ".git" in str(file_path)
        ):
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                lines = content.split("\n")

                for pattern in secret_patterns:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    for i, line in enumerate(lines):
                        # Skip comments and lines with obvious placeholders
                        if (
                            line.strip().startswith("#")
                            or "example" in line.lower()
                            or "placeholder" in line.lower()
                            or "test" in line.lower()
                            or "dummy" in line.lower()
                        ):
                            continue

                        if compiled_pattern.search(line):
                            print(f"⚠️  Potential secret in {file_path}:{i + 1}")
                            print(f"    Line: {line.strip()}")
                            secrets_found = True
        except Exception as e:
            print(f"⚠️  Could not scan {file_path}: {e}")

    if not secrets_found:
        print("✅ No hardcoded secrets detected")

    print("✅ Security checks completed")


def main():
    """Main test runner function"""
    print("🚀 AWS IAM Key Rotation - Test Suite Runner")
    print("=" * 50)

    # Check dependencies
    print("📦 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    print("✅ All dependencies available")

    # Run security checks
    run_security_checks()

    # Run tests
    success = run_tests()

    # Generate coverage report if coverage.py is available
    try:
        __import__("coverage")
        print("\n📈 Coverage analysis available")
        print("Run with: coverage run tests/run_tests.py && coverage report")
    except ImportError:
        print("\n💡 Install 'coverage' for test coverage analysis")

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
