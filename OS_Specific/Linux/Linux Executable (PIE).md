rule LinuxExecutablePIE
{
    meta:
        description = "Detects position-independent Linux executable files"
        author = "Bohdan Misonh"
        created = "2025-01-12"
        severity = "high"

    strings:
        $pie_magic = { 02 00 00 00 00 00 00 00 }  // PIE magic number in ELF file

    condition:
        $pie_magic at 0
}
