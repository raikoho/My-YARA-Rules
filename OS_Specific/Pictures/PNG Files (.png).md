```
rule MaliciousPNG
{
    meta:
        description = "Detects potentially malicious PNG files (.png)"
        author = "Bohdan Misonh"
        last_modified = "2025-02-11"
        severity = "medium"

    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }  // PNG file header

    condition:
        $png_header at 0
}
```

## Explanation: 

This rule detects PNG files by looking for the unique header `(89 50 4E 47 0D 0A 1A 0A)` that identifies PNG format files
