```
rule MaliciousVBS
{
    meta:
        description = "Detects malicious VBScript files (.vbs)"
        author = "Bohdan Misonh"
        last_modified = "2025-02-05"
        severity = "high"

    strings:
        $vbs_magic = { 0x2F 0x2A 0x2A 0x2F }  // Comments like "/*" or "//"
        $wscript_shell = "WScript.Shell"  // Common object used in malicious scripts
        $exec_command = "exec"  // Executes commands on the system
        $run_script = "Run("  // Executes a program or script

    condition:
        $vbs_magic at 0 or $wscript_shell or $exec_command or $run_script
}
```

## Explanation:

``$vbs_magic:`` Searches for comments or the beginning of VBScript code.

``$wscript_shell:`` Uses the WScript.Shell object, which is often used to execute commands on the system.

``$exec_command:`` Searches for the exec() function, which can execute malicious commands.

``$run_script:`` Searches for the Run() function, which can run scripts or programs.
