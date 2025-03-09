```
rule MaliciousGIF
{
    meta:
        description = "Detects potentially malicious GIF files (.gif)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-01"
        severity = "medium"

    strings:
        $gif_header = { 47 49 46 38 }  // GIF file header

    condition:
        $gif_header at 0
}
```

## Explanation: 

This rule identifies GIF files by searching for the header (47 49 46 38), which is unique to GIF images.
