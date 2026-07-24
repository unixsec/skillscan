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
        findings_json = "{\"test_item_id\":\"NET-02\",\"category\":\"network_intel\",\"severity\":\"CRITICAL\",\"title\":\"bash /dev/tcp 反弹 shell 特征\",\"risk\":\"该代码利用 bash 内建的 /dev/tcp 伪设备建立反弹 shell（reverse shell），一旦执行，会主动连接攻击者控制的服务器并把本机的命令行控制权交给对方，等同于完全的远程代码执行/后门。\"}"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i" ascii
    condition:
        $a and $b
}

rule net_reverse_shell_nc_exec {
    meta:
        findings_json = "{\"test_item_id\":\"NET-02\",\"category\":\"network_intel\",\"severity\":\"CRITICAL\",\"title\":\"netcat -e 执行 shell 特征\",\"risk\":\"该代码使用 netcat/ncat 的 -e 参数将 shell 绑定到网络连接，建立反弹 shell（reverse shell），一旦执行会把本机命令行控制权交给攻击者控制的远程主机，等同于完全的远程代码执行/后门。\"}"
    strings:
        $a = "nc -e /bin/sh" ascii
        $b = "nc -e /bin/bash" ascii
        $c = "ncat -e /bin/sh" ascii
    condition:
        any of them
}

rule net_reverse_shell_python_socket_subprocess {
    meta:
        findings_json = "{\"test_item_id\":\"NET-02\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"Python socket+subprocess 反弹 shell 骨架代码\",\"risk\":\"该代码组合了 socket 网络连接、文件描述符重定向（dup2）与子进程启动，是 Python 反弹 shell 的经典骨架结构，一旦执行会把本机命令行控制权交给攻击者控制的远程主机，等同于完全的远程代码执行/后门。\"}"
    strings:
        $socket = "socket.socket(socket.AF_INET" ascii
        $dup = "os.dup2(" ascii
        $exec = "subprocess.call([\"/bin/sh" ascii
    condition:
        $socket and ($dup or $exec)
}

rule code_webshell_php_eval_request {
    meta:
        findings_json = "{\"test_item_id\":\"CODE-04\",\"category\":\"code\",\"severity\":\"CRITICAL\",\"title\":\"PHP 对请求参数执行 eval 的 webshell 特征\",\"risk\":\"该代码把 HTTP 请求参数（$_POST/$_GET/$_REQUEST）直接传给 eval/assert 执行，是 PHP webshell 最典型的特征：一旦部署，任何能访问该端点的人都可以通过请求参数向服务器传入并执行任意 PHP 代码，等同于完全的远程代码执行后门。\"}"
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
        findings_json = "{\"test_item_id\":\"CODE-04\",\"category\":\"code\",\"severity\":\"CRITICAL\",\"title\":\"stratum 矿池协议字符串\",\"risk\":\"该代码包含 stratum 挖矿协议的连接字符串，是加密货币挖矿程序（cryptominer）用于连接矿池的特征标志；一旦执行会占用受害主机的算力/资源为攻击者挖矿牟利，属于资源滥用型恶意代码。\"}"
    strings:
        $a = "stratum+tcp://" ascii
        $b = "stratum+ssl://" ascii
    condition:
        any of them
}

rule supply_dependency_confusion_curl_pipe_shell {
    meta:
        findings_json = "{\"test_item_id\":\"NET-07\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"远程脚本直接管道传入 shell 解释器执行\",\"risk\":\"该代码使用 curl/wget 下载远程脚本并直接通过管道传给 shell 执行（curl | sh 模式），执行内容完全由远程服务器实时决定、未经任何本地审查或完整性校验；如果远程源被劫持或本身恶意，等同于把任意代码执行权限交给了该远程服务器的控制者。\"}"
    strings:
        $a = "curl" ascii
        $b = "| sh" ascii
        $c = "| bash" ascii
        $d = "wget" ascii
    condition:
        ($a or $d) and ($b or $c)
}
