```
rule WindowsScriptFileAlert
{
    meta:
        description = "Detects the opening of any Windows script file (.ps1, .cmd, .reg)"
        author = "Bohdan Misonh"
        last_modified = "2025-01-29"
        severity = "medium"

    strings:
        $ps1_magic = { 23 20 50 6F 77 65 72 73 68 20 53 63 72 69 70 74 }  // The start of a .ps1 file ('# Powershell Script')
        $cmd_magic = { 40 20 43 68 61 6E 6E 65 6C 20 }  // The start of a .cmd file ('@ Channel ')
        $reg_magic = { 5B 52 65 67 69 73 74 72 79 5D }  // The start of a .reg file ('[Registry]')
        
    condition:
        $ps1_magic at 0 or $cmd_magic at 0 or $reg_magic at 0
}

```

Windows scripts `(e.g. .ps1, .cmd, .reg)`: This is a general rule for typical Windows files such as `PowerShell (.ps1)`, `batch files (.cmd)`, `registry files (.reg)` that have specific magic numbers at the beginning.
