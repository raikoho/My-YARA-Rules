```
rule MaliciousBMP
{
    meta:
        description = "Detects potentially malicious BMP files (.bmp)"
        author = "Bohdan Misonh"
        last_modified = "2025-01-05"
        severity = "medium"

    strings:
        $bmp_header = { 42 4D }  // BMP file header

    condition:
        $bmp_header at 0
}
```

## Explanation: 

This rule detects BMP files by searching for the header `(42 4D)`, which is characteristic of the Bitmap format.
