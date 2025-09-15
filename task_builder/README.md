# CRS Task Builder

This script is used to build a task for the CRS (Code Review System). It creates a comprehensive package containing project source code, OSS-Fuzz, and diff files for analysis.

## Features

- Clones base and reference versions of a GitHub repository
- Downloads OSS-Fuzz at a specific version
- Generates diff between base and reference versions
- Creates a timestamped ZIP archive containing all components
- Comprehensive logging and error handling

## Requirements

- Python 3.6+
- Git installed and available in PATH
- Internet connection for cloning repositories

## Usage

### Basic Usage

```bash
python build_task.py \
  -r https://github.com/example/project \
  -b abc123def456 \
  -c def456ghi789 \
  -f xyz789abc123
```

### Full Usage with All Options

```bash
python build_task.py \
  -r https://github.com/example/project \
  -b abc123def456 \
  -c def456ghi789 \
  -o https://github.com/custom/oss-fuzz \
  -f xyz789abc123 \
  --output-dir ./custom_output \
  --zip-name my_custom_task
```

### Usage with Custom ZIP Name

```bash
python build_task.py \
  -r https://github.com/example/project \
  -b abc123def456 \
  -c def456ghi789 \
  -f xyz789abc123 \
  --zip-name spring-boot-analysis
```

## Parameters

- `-r, --base-github-repo-link`: Base GitHub repository URL (required)
- `-b, --base-github-repo-version`: Base repository version/commit hash (required)
- `-c, --reference-github-repo-version`: Reference repository version/commit hash (required)
- `-o, --oss-fuzz-link`: OSS-Fuzz repository URL (default: https://github.com/google/oss-fuzz)
- `-f, --oss-fuzz-version`: OSS-Fuzz version/commit hash (required)
- `--output-dir`: Output directory for the task (default: ./output)
- `--zip-name`: Custom name for the output ZIP file (without .zip extension)

## Output Structure

The script creates a ZIP file with the following structure:

```
crs_task_YYYYMMDD_HHMMSS.zip
├── repo/               # Base version source code (directly in repo folder)
├── diff/              # Diff directory
│   └── ref.diff       # Diff between base and reference versions
└── fuzz-tooling/      # OSS-Fuzz tool (directly in fuzz-tooling folder)
```

## Example

```bash
# Build a task for analyzing changes between two commits
python build_task.py \
  -r https://github.com/openssl/openssl \
  -b 1.1.1w \
  -c 3.0.12 \
  -f master
```

This will:
1. Clone OpenSSL repository at version 1.1.1w (base)
2. Clone OpenSSL repository at version 3.0.12 (reference)
3. Clone OSS-Fuzz at master branch
4. Generate diff between the two OpenSSL versions
5. Create a ZIP file containing all components

## Logging

The script creates detailed logs in `build_task.log` and outputs progress information to the console.

## Error Handling

The script includes comprehensive error handling for:
- Git command failures
- Network connectivity issues
- Invalid repository URLs or commit hashes
- File system permissions
- Disk space issues

## Notes

- The script removes `.git` directories from cloned repositories to save space
- If no differences are found between base and reference versions, an empty diff file is created
- Temporary directories are automatically cleaned up
- The final task directory is removed after ZIP creation to save disk space
