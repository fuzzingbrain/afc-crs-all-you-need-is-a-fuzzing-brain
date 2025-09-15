#!/usr/bin/env python3
"""
Test script for build_task.py

This script provides a simple way to test the build_task functionality
with sample parameters.
"""

import subprocess
import sys
import os
from pathlib import Path


def test_help():
    """Test the help functionality."""
    print("Testing help functionality...")
    try:
        result = subprocess.run([sys.executable, "build_task.py", "--help"], 
                              capture_output=True, text=True, check=True)
        print("✓ Help functionality works")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Help functionality failed: {e}")
        return False


def test_validation():
    """Test parameter validation."""
    print("Testing parameter validation...")
    try:
        # Test with missing required parameters
        result = subprocess.run([sys.executable, "build_task.py"], 
                              capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print("✓ Parameter validation works (correctly rejects missing parameters)")
            return True
        else:
            print("✗ Parameter validation failed (should reject missing parameters)")
            return False
    except Exception as e:
        print(f"✗ Parameter validation test failed: {e}")
        return False


def test_dry_run():
    """Test with a small repository (dry run simulation)."""
    print("Testing with sample parameters...")
    
    # Use a small, public repository for testing
    test_params = [
        sys.executable, "build_task.py",
        "-r", "https://github.com/octocat/Hello-World",
        "-b", "master",
        "-c", "master", 
        "-f", "master",
        "--output-dir", "./test_output"
    ]
    
    print(f"Running: {' '.join(test_params)}")
    print("Note: This will actually clone repositories and may take some time...")
    
    try:
        result = subprocess.run(test_params, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            print("✓ Test run completed successfully")
            # Check if output file was created
            output_dir = Path("./test_output")
            if output_dir.exists():
                zip_files = list(output_dir.glob("*.zip"))
                if zip_files:
                    print(f"✓ Output ZIP file created: {zip_files[0]}")
                    return True
                else:
                    print("✗ No ZIP file found in output directory")
                    return False
            else:
                print("✗ Output directory not created")
                return False
        else:
            print(f"✗ Test run failed with return code: {result.returncode}")
            print(f"Error output: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Test run failed with exception: {e}")
        return False


def cleanup_test_output():
    """Clean up test output directory."""
    test_output = Path("./test_output")
    if test_output.exists():
        import shutil
        shutil.rmtree(test_output)
        print("✓ Cleaned up test output directory")


def main():
    """Run all tests."""
    print("Running build_task.py tests...\n")
    
    tests = [
        ("Help Test", test_help),
        ("Validation Test", test_validation),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        if test_func():
            passed += 1
        print()
    
    print(f"Tests completed: {passed}/{total} passed")
    
    # Ask user if they want to run the full test
    if passed == total:
        print("\nBasic tests passed! Would you like to run a full test with actual repository cloning?")
        print("This will download repositories and may take several minutes. (y/N): ", end="")
        
        try:
            response = input().strip().lower()
            if response in ['y', 'yes']:
                print("\n--- Full Test ---")
                if test_dry_run():
                    print("✓ Full test completed successfully")
                    passed += 1
                total += 1
                cleanup_test_output()
        except KeyboardInterrupt:
            print("\nTest interrupted by user")
            cleanup_test_output()
    
    print(f"\nFinal results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
