rule ZIPArchive
{
    meta:
        description = "Detects ZIP archive files (.zip)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-09"
        severity = "medium"

    strings:
        $zip_magic = { 50 4B 03 04 }  // Magic number for ZIP files (PK..)

    condition:
        $zip_magic at 0
}
