```
rule MaliciousJPEG
{
    meta:
        description = "Detects potentially malicious JPEG files (.jpg, .jpeg)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-01"
        severity = "medium"

    strings:
        $jpg_header = { FF D8 FF E0 }  // JPEG file header

    condition:
        $jpg_header at 0
}
```

## Explanation: 

This rule detects JPEG files by looking for the specific file header (FF D8 FF E0), which is common in JPEG files.
