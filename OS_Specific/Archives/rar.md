```
rule RARArchive
{
    meta:
        description = "Detects RAR archive files (.rar)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-08"
        severity = "medium"

    strings:
        $rar_magic = { 52 61 72 21 1A 07 00 }  // Magic number for RAR files (RAR!)

    condition:
        $rar_magic at 0
}
```
