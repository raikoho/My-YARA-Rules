```
rule MaliciousRTF
{
    meta:
        description = "Detects malicious RTF document files (.rtf)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-09"
        severity = "medium"

    strings:
        $rtf_magic = { 7B 5C 72 74 66 31 20 31 2E }  // Magic number for .rtf (starts with '{\rtf1')

    condition:
        $rtf_magic at 0
}
```

## Explanation:

``$rtf_magic:`` This is the magic number for .rtf files, which starts with the bytes { 7B 5C 72 74 66 31 20 31 2E }, indicating the beginning of RTF files ({\rtf1).
