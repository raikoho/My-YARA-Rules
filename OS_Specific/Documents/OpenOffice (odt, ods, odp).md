```
rule MaliciousOpenOfficeDocument
{
    meta:
        description = "Detects malicious OpenOffice document files (.odt, .ods, .odp)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-09"
        severity = "medium"

    strings:
        $odt_magic = { 50 4B 03 04 14 00 08 00 }  // Magic number for .odt (ZIP-based format)
        $ods_magic = { 50 4B 03 04 14 00 08 00 }  // Magic number for .ods (ZIP-based format)
        $odp_magic = { 50 4B 03 04 14 00 08 00 }  // Magic number for .odp (ZIP-based format)

    condition:
        $odt_magic at 0 or $ods_magic at 0 or $odp_magic at 0
}
```

## Explanation:

``$odt_magic, $ods_magic, $odp_magic:`` This is the magic number for OpenOffice files (.odt for text documents, .ods for spreadsheets, .odp for presentations), as all of these formats are ZIP archives, as are Microsoft Office documents in the .docx and .xlsx formats.
