rule argus_test {
    strings:
        $a = "ARGUS_TEST_PAYLOAD"
    condition:
        $a
}