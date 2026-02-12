# Local Scan Mode

Run FuzzingBrain directly on a GitHub URL or local workspace.

## Usage

### From GitHub URL

```bash
# Full scan
./FuzzingBrain.sh https://github.com/pnggroup/libpng.git

# With options
./FuzzingBrain.sh \
  --job-type pov-patch \
  --sanitizers address,memory \
  --timeout 120 \
  https://github.com/pnggroup/libpng.git
```

### From Local Workspace

```bash
# Use existing workspace
./FuzzingBrain.sh workspace/libpng_abc123

# In-place (don't copy)
./FuzzingBrain.sh --in-place workspace/libpng_abc123
```

### Continue Project

```bash
# Continue by project name (finds latest workspace)
./FuzzingBrain.sh libpng_abc123
```

## Test

```bash
./run.sh
```
