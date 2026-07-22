/*
 * Project-authored YARA rules (services/engine_runner/adapters/yara.py's
 * `findings_json` meta convention). No project-authored rules existed here
 * before - the yara adapter existed and was tested, but had nothing to
 * actually scan with. These are original rules covering well-documented,
 * generic indicator classes (reverse-shell command patterns, common webshell
 * entry points, cryptominer terminology) - not copied from any specific
 * third-party ruleset.
 *
 * Each rule's `findings_json` meta value matches
 * `libs/schemas/findings.py`'s `FindingDTO` shape closely enough for
 * `yara.py`'s `parse_output` to map directly: test_item_id/category/severity/
 * title. `category` must be one of skillscan_core.models.DetectionCategory's
 * values (lowercase, e.g. "network_intel", "code") - checked against
 * libs/skillscan_core/models.py directly, not guessed.
 */

rule net_reverse_shell_bash_dev_tcp {
    meta:
        findings_json = "{\"test_item_id\":\"NET-02\",\"category\":\"network_intel\",\"severity\":\"CRITICAL\",\"title\":\"bash /dev/tcp reverse shell pattern\"}"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i" ascii
    condition:
        $a and $b
}

rule net_reverse_shell_nc_exec {
    meta:
        findings_json = "{\"test_item_id\":\"NET-02\",\"category\":\"network_intel\",\"severity\":\"CRITICAL\",\"title\":\"netcat -e exec-a-shell pattern\"}"
    strings:
        $a = "nc -e /bin/sh" ascii
        $b = "nc -e /bin/bash" ascii
        $c = "ncat -e /bin/sh" ascii
    condition:
        any of them
}

rule net_reverse_shell_python_socket_subprocess {
    meta:
        findings_json = "{\"test_item_id\":\"NET-02\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"Python socket+subprocess reverse-shell scaffold\"}"
    strings:
        $socket = "socket.socket(socket.AF_INET" ascii
        $dup = "os.dup2(" ascii
        $exec = "subprocess.call([\"/bin/sh" ascii
    condition:
        $socket and ($dup or $exec)
}

rule code_webshell_php_eval_request {
    meta:
        findings_json = "{\"test_item_id\":\"CODE-04\",\"category\":\"code\",\"severity\":\"CRITICAL\",\"title\":\"PHP eval-of-request webshell pattern\"}"
    strings:
        $a = "eval($_POST" ascii
        $b = "eval($_GET" ascii
        $c = "eval($_REQUEST" ascii
        $d = "assert($_POST" ascii
    condition:
        any of them
}

rule code_cryptominer_stratum_protocol {
    meta:
        findings_json = "{\"test_item_id\":\"CODE-04\",\"category\":\"code\",\"severity\":\"CRITICAL\",\"title\":\"stratum mining-pool protocol string\"}"
    strings:
        $a = "stratum+tcp://" ascii
        $b = "stratum+ssl://" ascii
    condition:
        any of them
}

rule supply_dependency_confusion_curl_pipe_shell {
    meta:
        findings_json = "{\"test_item_id\":\"NET-07\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"remote script piped directly into a shell interpreter\"}"
    strings:
        $a = "curl" ascii
        $b = "| sh" ascii
        $c = "| bash" ascii
        $d = "wget" ascii
    condition:
        ($a or $d) and ($b or $c)
}
