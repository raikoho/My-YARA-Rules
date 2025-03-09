```
rule MaliciousPDF
{
    meta:
        description = "Detects malicious PDF document files (.pdf)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-09"
        severity = "high"

    strings:
        $pdf_magic = { 25 50 44 46 2D }  // Magic number for PDF files (start with '%PDF-')

    condition:
        $pdf_magic at 0
}
```

## Explanation:

``$pdf_magic:`` This is the magic number for .pdf files, which starts with bytes 25 50 44 46 2D, which corresponds to the characters %PDF-, which is the beginning of PDF documents.
