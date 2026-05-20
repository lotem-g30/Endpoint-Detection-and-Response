rule MZ_in_private_memory {
    meta:
        description = "PE header found in private (non-image) memory — possible reflective load"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule suspicious_string {
    meta:
        description = "Known-bad test string in memory"
    strings:
        $s = "ARGUS_TEST_PAYLOAD" ascii
    condition:
        $s
}