# Job Types

Different task types supported by FuzzingBrain.

## Available Job Types

| Type | Description |
|------|-------------|
| `pov` | Find vulnerabilities only |
| `patch` | Generate patches for known POVs |
| `pov-patch` | Find vulnerabilities + generate patches (default) |
| `harness` | Generate fuzzing harnesses |

## Usage

```bash
# POV only
./FuzzingBrain.sh --job-type pov https://github.com/user/repo.git

# Patch only (requires existing POV)
./FuzzingBrain.sh --job-type patch workspace/project_abc123

# POV + Patch (default)
./FuzzingBrain.sh --job-type pov-patch https://github.com/user/repo.git

# Harness generation
./FuzzingBrain.sh --job-type harness https://github.com/user/repo.git
```

## Test

```bash
./run_pov.sh      # POV only mode
./run_patch.sh    # Patch mode
./run_harness.sh  # Harness mode
```
