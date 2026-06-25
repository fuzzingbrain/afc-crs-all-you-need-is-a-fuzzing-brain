# JSON Config Mode

Load task configuration from a JSON file.

## Usage

```bash
./FuzzingBrain.sh config.json
```

## Config Format

See example configs in this folder:

- `full_scan.json` - Basic full scan
- `delta_scan.json` - Delta scan between commits
- `harness.json` - Harness generation with targets

## Test

```bash
./run.sh
```
