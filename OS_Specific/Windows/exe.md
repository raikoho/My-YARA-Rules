```
rule ExecutableFileAlert
{
    meta:
        description = "Detects the opening of any .exe file"
        author = "Bohdan Misonh"
        last_modified = "2025-01-29"
        severity = "medium"

    strings:
        $exe_magic = { 4D 5A 90 00 00 00 00 00 }  // The magic number for .exe files (MZ header)

    condition:
        $exe_magic at 0
}
```

`$exe_magic`: This is the magic number that is the first byte in any .exe file. It starts with 4D 5A, which is the well-known "MZ" header for .exe executables.

`at 0`: This means that we look for this magic number at the beginning of the file, which is standard for all .exe executables.
