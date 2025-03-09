```
rule LinuxTarArchive
{
    meta:
        description = "Detects Linux archive files (.tar.gz, .tar.bz2, .tar.xz)"
        author = "Bohdan Misonh"
        created = "2025-01-15"
        severity = "medium"

    strings:
        $tar_magic = { 75 73 74 61 72 20 }  // Magic number for .tar files (starts with 'ustar ')
        $gzip_magic = { 1F 8B }             // Magic number for .gz files (starts with 1F 8B)
        $bzip2_magic = { 42 5A 68 }         // Magic number for .bz2 files (starts with 'BZh')
        $xz_magic = { FD 37 7A 58 5A 00 }   // Magic number for .xz files (starts with 'xz')

    condition:
        $tar_magic at 0 or $gzip_magic at 0 or $bzip2_magic at 0 or $xz_magic at 0
}
```
