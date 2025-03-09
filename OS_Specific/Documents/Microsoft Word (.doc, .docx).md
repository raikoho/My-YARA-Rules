```
rule MaliciousWordDocument
{
    meta:
        description = "Detects malicious Microsoft Word document files (.doc, .docx)"
        author = "Bohdan Misonh"
        last_modified = "2025-02-03"
        severity = "high"

    strings:
        $doc_magic = { D0 CF 11 E0 A1 B1 1A E1 }  // Magic number for .doc (OLE2 files)
        $docx_magic = { 50 4B 03 04 14 00 08 00 }  // Magic number for .docx (ZIP-based format)

    condition:
        $doc_magic at 0 or $docx_magic at 0
}
```

## Explanation:

``$doc_magic:`` This is the magic number for old .doc files (OLE2 files), which starts with bytes D0 CF 11 E0 A1 B1 1A E1.

``$docx_magic:`` This is the magic number for .docx files, which starts with bytes 50 4B 03 04 14 00 08 00, which indicates a ZIP archive, since .docx documents are actually archives.
