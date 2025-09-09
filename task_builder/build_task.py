"""
This script is used to build a task for the CRS.

A (delta) task should contain:
- project source code
- oss-fuzz
- diff

Input to this script:
- base github repo link and version (base version, commit hash)
- reference github repo link and version (version you want to scan, commit hash)
- oss-fuzz link and version (your fuzzing tool, commit hash)

Output:
A zipped file containing:
- project source code
- oss-fuzz
- diff
"""

import argparse
import os
import sys
import subprocess
import tempfile
import shutil
import zipfile
import logging
from pathlib import Path
from datetime import datetime


def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('build_task.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def run_command(command, cwd=None, check=True):
    """Run a shell command and return the result."""
    logging.info(f"Running command: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            check=check,
            capture_output=True,
            text=True
        )
        if result.stdout:
            logging.info(f"Command output: {result.stdout}")
        return result
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
        logging.error(f"Error output: {e.stderr}")
        raise


def clone_repository(repo_url, version, target_dir, repo_name):
    """Clone a git repository to the target directory."""
    logging.info(f"Cloning {repo_name} from {repo_url} at version {version}")
    
    # Clone the repository
    run_command(f"git clone {repo_url} {target_dir}")
    
    # Checkout the specific version
    try:
        run_command(f"git checkout {version}", cwd=target_dir)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to checkout version {version} for {repo_name}")
        logging.error(f"This might be because:")
        logging.error(f"1. The commit hash '{version}' doesn't exist in the repository")
        logging.error(f"2. The branch/tag '{version}' doesn't exist")
        logging.error(f"3. You don't have access to the repository")
        logging.error(f"Please verify the version/commit hash and try again.")
        raise
    
    # Remove .git directory to save space
    git_dir = os.path.join(target_dir, '.git')
    if os.path.exists(git_dir):
        shutil.rmtree(git_dir)
    
    logging.info(f"Successfully cloned {repo_name}")


def generate_diff(base_repo_path, reference_repo_path, output_path):
    """Generate diff between base and reference repositories."""
    logging.info("Generating diff between base and reference repositories")
    
    # Create a temporary directory for the diff
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone base repo to temp directory
        base_temp = os.path.join(temp_dir, 'base')
        run_command(f"git clone {base_repo_path} {base_temp}")
        
        # Clone reference repo to temp directory
        ref_temp = os.path.join(temp_dir, 'reference')
        run_command(f"git clone {reference_repo_path} {ref_temp}")
        
        # Generate diff
        diff_file = os.path.join(output_path, 'diff.patch')
        run_command(f"diff -u -r {base_temp} {ref_temp} > {diff_file}", check=False)
        
        # If diff is empty, create an empty file
        if os.path.getsize(diff_file) == 0:
            with open(diff_file, 'w') as f:
                f.write("# No differences found between base and reference versions\n")
        
        logging.info(f"Diff generated and saved to {diff_file}")


def generate_diff_local(base_dir, reference_dir, output_path):
    """Generate diff between local base and reference directories."""
    logging.info("Generating diff between local base and reference directories")
    
    # Generate diff
    diff_file = os.path.join(output_path, 'diff.patch')
    run_command(f"diff -u -r {base_dir} {reference_dir} > {diff_file}", check=False)
    
    # If diff is empty, create an empty file
    if os.path.getsize(diff_file) == 0:
        with open(diff_file, 'w') as f:
            f.write("# No differences found between base and reference versions\n")
    
    logging.info(f"Diff generated and saved to {diff_file}")


def create_zip_archive(source_dir, output_file):
    """Create a zip archive from the source directory."""
    logging.info(f"Creating zip archive: {output_file}")
    
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, source_dir)
                zipf.write(file_path, arcname)
    
    logging.info(f"Zip archive created successfully: {output_file}")


def main():
    """
    Build a task for the CRS system.
    
    Parameters:
    -r, --base-github-repo-link: base github repo link
    -b, --base-github-repo-version: base github repo version
    -c, --reference-github-repo-version: reference github repo version
    -o, --oss-fuzz-link: oss-fuzz link, default: https://github.com/google/oss-fuzz
    -f, --oss-fuzz-version: oss-fuzz version
    """
    
    setup_logging()
    
    parser = argparse.ArgumentParser(description='Build a task for the CRS system')
    parser.add_argument('-r', '--base-github-repo-link', required=True,
                       help='Base github repo link')
    parser.add_argument('-b', '--base-github-repo-version', required=True,
                       help='Base github repo version (commit hash)')
    parser.add_argument('-c', '--reference-github-repo-version', required=True,
                       help='Reference github repo version (commit hash)')
    parser.add_argument('-o', '--oss-fuzz-link', 
                       default='https://github.com/google/oss-fuzz',
                       help='OSS-Fuzz link (default: https://github.com/google/oss-fuzz)')
    parser.add_argument('-f', '--oss-fuzz-version', required=True,
                       help='OSS-Fuzz version (commit hash)')
    parser.add_argument('--output-dir', default='./output',
                       help='Output directory for the task (default: ./output)')
    parser.add_argument('--zip-name', 
                       help='Custom name for the output ZIP file (without .zip extension)')
    
    args = parser.parse_args()
    
    # Validate that git is available
    try:
        run_command("git --version")
    except subprocess.CalledProcessError:
        logging.error("Git is not installed or not available in PATH")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped task directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    task_dir = output_dir / f"task_{timestamp}"
    task_dir.mkdir(exist_ok=True)
    
    try:
        # Create the three required directories
        repo_dir = task_dir / "repo"
        diff_dir = task_dir / "diff"
        fuzz_tooling_dir = task_dir / "fuzz-tooling"
        
        repo_dir.mkdir(exist_ok=True)
        diff_dir.mkdir(exist_ok=True)
        fuzz_tooling_dir.mkdir(exist_ok=True)
        
        # Clone base repository (source code) directly into repo folder
        clone_repository(
            args.base_github_repo_link,
            args.base_github_repo_version,
            str(repo_dir),
            "base repository"
        )
        
        # Clone reference repository for diff generation (temporary)
        temp_reference_dir = task_dir / "temp_reference"
        clone_repository(
            args.base_github_repo_link,  # Same repo, different version
            args.reference_github_repo_version,
            str(temp_reference_dir),
            "reference repository"
        )
        
        # Clone OSS-Fuzz directly into fuzz-tooling folder
        clone_repository(
            args.oss_fuzz_link,
            args.oss_fuzz_version,
            str(fuzz_tooling_dir),
            "OSS-Fuzz"
        )
        
        # Generate diff between base and reference
        generate_diff_local(
            str(repo_dir),
            str(temp_reference_dir),
            str(diff_dir)
        )
        
        # Rename diff file to ref.diff
        diff_file = diff_dir / "diff.patch"
        ref_diff_file = diff_dir / "ref.diff"
        if diff_file.exists():
            diff_file.rename(ref_diff_file)
        
        # Clean up temporary reference directory
        if temp_reference_dir.exists():
            shutil.rmtree(temp_reference_dir)
        
        # Create zip archive
        if args.zip_name:
            zip_filename = output_dir / f"{args.zip_name}.zip"
        else:
            zip_filename = output_dir / f"crs_task_{timestamp}.zip"
        create_zip_archive(str(task_dir), str(zip_filename))
        
        # Clean up task directory
        shutil.rmtree(task_dir)
        
        logging.info(f"Task built successfully: {zip_filename}")
        print(f"Task built successfully: {zip_filename}")
        
    except Exception as e:
        logging.error(f"Error building task: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()