# SUID File Enumerator

Finds files with the SUID bit set that could be exploited for privilege escalation.

## Usage

```bash
chmod +x enumerator.sh
sudo ./enumerator.sh [directory] [output_file]
```

Defaults: /, /tmp/suid_files.txt
