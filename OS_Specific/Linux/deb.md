rule LinuxDebianPackage
{
    meta:
        description = "Detects Linux Debian package files (.deb)"
        author = "Bohdan Misonh"
        created = "2025-01-20"
        severity = "medium"

    strings:
        $deb_magic = { 21 3C 61 72 63 68 3E 0A }  // Magic number for .deb files (beginning of control information)
        
    condition:
        $deb_magic at 0
}
