```
rule LinuxExecutableELF
{
    meta:
        description = "Detects Linux executable ELF files"
        author = "Bohdan Misonh"
        last_modified = "2025-01-29"
        severity = "high"

    strings:
        $elf_magic = { 7F 45 4C 46 }  // ELF magic number (7F 45 4C 46)
        
    condition:
        $elf_magic at 0
}
```
