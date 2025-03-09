```
rule MaliciousJS
{
    meta:
        description = "Detects malicious JavaScript files (.js)"
        author = "Bohdan Misonh"
        last_modified = "2025-03-09"
        severity = "high"

    strings:
        $js_magic = { 2F 2A 2A 2F }  // Comments like "/*" or "//"
        $eval_function = "eval("  // Common function used for obfuscation
        $document_write = "document.write("  // Common function used in malicious JS
        $http_request = "http"  // Potential malicious HTTP requests

    condition:
        $js_magic at 0 or $eval_function or $document_write or $http_request
}
```

## Explanation:

``$js_magic:`` Searches for comments or the beginning of JavaScript code.

``$eval_function:`` Uses the eval() function, which is often used to execute dynamically processed code.

``$document_write:`` Used to dynamically write to a document, which can be used for malicious scripts.

``$http_request:`` Searches for HTTP requests, which can be part of malicious JavaScript to transfer data.

