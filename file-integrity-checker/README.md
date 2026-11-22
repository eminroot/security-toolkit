# File Integrity Checker (Hash-based)

Creates baseline hashes of files and verifies integrity to detect modifications.

## Usage

```bash
chmod +x checker.sh
./checker.sh create [baseline_file] [directory]   # Create baseline
./checker.sh verify [baseline_file]               # Verify against baseline
```

Algorithm: sha256 (default)
