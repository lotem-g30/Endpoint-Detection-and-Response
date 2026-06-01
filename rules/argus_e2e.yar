/*
 * argus_e2e.yar — YARA rule loaded by argus_agent for E2E testing.
 *
 * Contains ONLY the suspicious_string rule so the CRITICAL verdict fires
 * exactly when test_target.exe writes ARGUS_TEST_PAYLOAD into its allocated
 * buffer, and not on the MZ headers of every loaded DLL.
 */

rule suspicious_string {
    meta:
        description = "E2E test marker written by test_target.exe"
        test_use    = "Fired by the Trinity injection sequence in e2e_full_system_test.py"
    strings:
        $s = "ARGUS_TEST_PAYLOAD" ascii
    condition:
        $s
}
