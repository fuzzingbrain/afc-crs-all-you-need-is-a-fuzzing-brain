# Delta Scan Mode

Scan only the changes between two commits.

## Usage

```bash
# Delta scan with base and target commits
./FuzzingBrain.sh \
  -b <base_commit> \
  -d <delta_commit> \
  https://github.com/user/repo.git

# -b automatically sets scan_mode to "delta"
# -d is optional (defaults to HEAD)
```

## Example

```bash
./FuzzingBrain.sh \
  -b bc841a89aea42b2a2de752171588ce94402b3949 \
  -d 2c894c66108f0724331a9e5b4826e351bf2d094b \
  https://github.com/OwenSanzas/libpng.git
```

## Test

```bash
./run.sh
```
