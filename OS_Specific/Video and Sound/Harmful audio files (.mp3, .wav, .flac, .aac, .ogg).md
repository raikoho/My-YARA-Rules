```
rule MaliciousAudioFiles
{
    meta:
        description = "Detects potentially malicious audio files (.mp3, .wav, .flac, .aac, .ogg)"
        author = "Bohdan Misonh"
        last_modified = "2025-02-12"
        severity = "medium"

    strings:
        $mp3_header = { 49 44 33 }  // "ID3" header for MP3 files
        $wav_header = { 52 49 46 46 }  // "RIFF" header for WAV files
        $flac_header = { 66 4C 61 43 00 00 00 22 }  // FLAC file header
        $aac_header = { 0xFF 0xF1 }  // AAC header, used in many audio files
        $ogg_header = { 4F 67 67 53 }  // "OggS" header for OGG files

    condition:
        $mp3_header at 0 or $wav_header at 0 or $flac_header at 0 or $aac_header at 0 or $ogg_header at 0
}
```

## Explanation:

``$mp3_header:`` Identifies MP3 files using the "ID3" header, which is often used in audio file metadata.

``$wav_header:`` Looks for the "RIFF" header, which is typical for WAV files.

``$flac_header:`` Identifies FLAC files using their specific header.

``$aac_header:`` Identifies AAC files using their header.

``$ogg_header:`` Looks for the "OggS" header, which is typical for OGG audio files.

These rules allow you to filter audio files by their headers and help identify suspicious files that may contain malicious code.
