```
rule CABArchive
{
    meta:
        description = "Detects CAB archive files (.cab)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-03"
        severity = "medium"

    strings:
        $cab_magic = { 4D 53 43 46 00 00 00 00 }  // Magic number for CAB files (MSCF)

    condition:
        $cab_magic at 0
}
```
