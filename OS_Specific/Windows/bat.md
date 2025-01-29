```
rule BatchFileAlert
{
    meta:
        description = "Detects the opening of any .bat file"
        author = "Bohdan Misonh"
        last_modified = "2025-01-29"
        severity = "medium"

    strings:
        $bat_magic = { 40 42 41 54 20 }  // The magic number for .bat files (starting with '@BAT ')
        
    condition:
        $bat_magic at 0
}
```

Search for a specific pattern that indicates the typical structure of `.bat` files.
