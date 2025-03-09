rule LinuxShellScript
{
    meta:
        description = "Detects Linux shell script files (.sh)"
        author = "Bohdan Misonh"
        created = "2025-01-05"
        severity = "medium"

    strings:
        $sh_magic = "#!/bin/bash"  // Common shebang for bash scripts

    condition:
        $sh_magic at 0
}
