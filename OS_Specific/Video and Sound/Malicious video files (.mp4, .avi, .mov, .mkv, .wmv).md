```
rule MaliciousVideoFiles
{
    meta:
        description = "Detects potentially malicious video files (.mp4, .avi, .mov, .mkv, .wmv)"
        author = "Bohdan Misonh"
        last_modified = "2025-01-02"
        severity = "high"

    strings:
        $mp4_header = { 00 00 00 18 66 74 79 70 33 67 }  // "ftyp" header for MP4 files
        $avi_header = { 52 49 46 46 }  // "RIFF" header for AVI files
        $mov_header = { 00 00 00 18 66 74 79 70 71 74 20 }  // MOV file header
        $mkv_header = { 1A 45 DF A3 93 42 82 }  // Matroska (MKV) header
        $wmv_header = { 30 26 B2 75 8E 66 CF 11 }  // WMV header

    condition:
        $mp4_header at 0 or $avi_header at 0 or $mov_header at 0 or $mkv_header at 0 or $wmv_header at 0
}
```

## Explanation:

``$mp4_header:`` Searches for the opening bytes of MP4 files, including the "ftyp" header.

``$avi_header:`` Identifies AVI files using the "RIFF" header.

``$mov_header:`` Identifies MOV files using a header specific to that format.

``$mkv_header:`` Found a set of bytes for Matroska (MKV) files.

$wmv_header: Identifies WMV files using a unique header.
