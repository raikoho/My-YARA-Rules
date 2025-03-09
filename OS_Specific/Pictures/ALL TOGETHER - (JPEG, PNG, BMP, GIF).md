```
rule MaliciousImageFiles
{
    meta:
        description = "Detects potentially malicious image files (.jpg, .png, .bmp, .gif)"
        author = "Bohdan Misonh"
        last_modified = "2025-02-15"
        severity = "medium"

    strings:
        $jpg_header = { FF D8 FF E0 }  // JPEG file header
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }  // PNG file header
        $bmp_header = { 42 4D }  // BMP file header
        $gif_header = { 47 49 46 38 }  // GIF file header

    condition:
        $jpg_header at 0 or $png_header at 0 or $bmp_header at 0 or $gif_header at 0
}
```

## Explanation:

``$jpg_header:`` Identifies JPEG files by a specific header.

``$png_header:`` Looks for the PNG header, which is unique to that format.

``$bmp_header:`` Looks for the BMP header, which identifies the file format as Bitmap.
$gif_header: Detects GIF files by their standard bytes at the beginning of the file.
