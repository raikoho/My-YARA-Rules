```
rule TARArchiveSimple
{
    meta:
        description = "Detects basic TAR archive files (.tar)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-09"
        severity = "medium"

    strings:
        $tar_magic = { 75 73 74 61 72 20 }  // Magic number for .tar files (starts with 'ustar')

    condition:
        $tar_magic at 0
}
```

$tar_magic: This is the magic number for .tar archives, which starts with bytes 75 73 74 61 72 20 (corresponds to "ustar").
