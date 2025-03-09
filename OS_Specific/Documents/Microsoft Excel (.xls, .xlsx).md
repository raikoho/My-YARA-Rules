```
rule MaliciousExcelDocument
{
    meta:
        description = "Detects malicious Microsoft Excel document files (.xls, .xlsx)"
        author = "Bohdan Misonh"
        last_modified = "2025-01-06"
        severity = "high"

    strings:
        $xls_magic = { D0 CF 11 E0 A1 B1 1A E1 }  // Magic number for .xls (OLE2 files)
        $xlsx_magic = { 50 4B 03 04 14 00 08 00 }  // Magic number for .xlsx (ZIP-based format)

    condition:
        $xls_magic at 0 or $xlsx_magic at 0
}
```

## Explanation:

``$xls_magic:`` This is the magic number for old .xls files (OLE2 files), which starts with bytes D0 CF 11 E0 A1 B1 1A E1.

``$xlsx_magic:`` This is the magic number for .xlsx files, which starts with bytes 50 4B 03 04 14 00 08 00, which indicates a ZIP archive, since .xlsx documents are archives.
