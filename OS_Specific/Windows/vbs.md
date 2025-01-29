```
rule VBScriptFileAlert
{
    meta:
        description = "Detects the opening of any .vbs file"
        author = "Bohdan Misonh"
        last_modified = "2025-01-29"
        severity = "medium"

    strings:
        $vbs_magic = { 22 3C 3F 76 62 73 63 72 69 70 74 20 }  // The start of a .vbs file (<?vbscript)
        
    condition:
        $vbs_magic at 0
}
```

Searches for the beginning of VBScript files, which usually starts with `<?vbscript`.
