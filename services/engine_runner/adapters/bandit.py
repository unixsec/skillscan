"""bandit adapter (coding spec §10: `bandit -f json`) → CODE-10 弱加密,
FILE-06 TOCTOU/符号链接, CODE-01 命令注入, CODE-08 SQL注入, CODE-02 动态执行,
CODE-07 不安全反序列化.

Real JSON schema confirmed by reading `vendor/bandit/bandit/formatters/json.py`
directly (coding spec's own instruction - read the real vendored source,
don't guess the interface):
  {"results": [{"filename", "issue_confidence", "issue_severity",
    "issue_cwe": {"id","link"}, "issue_text", "line_number", "line_range",
    "test_name", "test_id"}], "errors": [...], "metrics": {...}}

SECURITY: bandit exits 1 (not 0) when it finds issues at/above its default
threshold - that is NOT a crash, so `treat_nonzero_exit_as_error=False` here;
stdout JSON-parseability is what actually determines usability (a genuine
crash produces no valid JSON, which still fails closed via the parser
raising).

test_item_id mapping (2026-07-27 hardening, D7): this adapter used to pass
bandit's own `test_id` (e.g. "B608") straight through to `test_item_id`
whenever it wasn't one of the two originally-mapped groups below - a raw
engine id never matches a detection-catalog id, so every one of those
findings counted as UNCOVERED in any report keyed on the catalog (the
systemic problem `doc/devfile/oss-vs-custom-report.html` documented
2026-07-09). Fixed two ways: (1) the two pre-existing groups were themselves
mislabelled (CODE-12 is "进程创建"/process creation in the catalog, not weak
crypto; FILE-04 is "任意文件读取"/arbitrary file read, not TOCTOU/symlink) -
corrected to CODE-10/FILE-06. (2) added explicit groups for the common
still-unmapped cases (command injection, SQLi, dynamic execution, insecure
deserialization) and changed the fallback from "pass the raw bandit id
through" to the catalog's own explicit "detected but unclassified" marker,
GEN-01 (企业Skill安全评估测试维度清单.xlsx, D10) - honest about the gap
instead of silently reading as a coverage hole.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    Finding,
    Severity,
)

from ..timeouts import DEFAULT_ENGINE_TIMEOUT_S
from .base import SubprocessEngineAdapter

# SECURITY: bandit test IDs the coding spec explicitly names as mapping to a
# specific detection-catalog item; everything else falls back to GEN-01 (see
# module docstring's 2026-07-27 note) - honest about not having built a full
# 70+-rule mapping table, rather than leaking the raw bandit id through.
#
# 2026-07-27：原 _FILE_04_TEST_IDS 与检测目录不符——FILE-04 是「任意文件读取」，
# 不是 TOCTOU/临时目录风险；B108 (hardcoded_tmp_directory) 实际对应 FILE-06
# 「临时文件与符号链接风险」，已改名+改值。
_FILE_06_TEST_IDS = frozenset({"B108"})  # hardcoded_tmp_directory
# 2026-07-27：原 _CODE_12_TEST_IDS 与检测目录不符——CODE-12 是「进程创建」，不是
# 弱加密；这组 test_id 实际对应 CODE-10「弱加密」，已改名+改值。
# weak crypto/random: B303-B305/B311 are bandit's older blacklist-style IDs;
# B324 ("hashlib") is the current AST-based plugin that actually fires for
# `hashlib.md5(...)`/`hashlib.sha1(...)` on the installed bandit 1.9.4 CLI
# (confirmed empirically - a live hashlib.md5() sample emits B324, not B303).
_CODE_10_TEST_IDS = frozenset({"B303", "B304", "B305", "B311", "B324"})
# 2026-07-27（D7 新增映射，覆盖此前透传原始 bandit ID 的常见情形）：
# command injection / system command execution - subprocess/shell family.
_CODE_01_TEST_IDS = frozenset({"B602", "B603", "B605", "B607"})
# SQL injection - hardcoded SQL string construction.
_CODE_08_TEST_IDS = frozenset({"B608"})
# dynamic code execution - eval() on a possibly-untrusted string.
_CODE_02_TEST_IDS = frozenset({"B307"})
# insecure deserialization - pickle/dill/shelve of untrusted data. NOTE: this
# is intentionally separate from _CODE_02_TEST_IDS above, even though both are
# "unsafe interpretation of data" in spirit - the catalog carries a dedicated
# CODE-07「不安全反序列化」item (企业Skill安全评估测试维度清单 D2) distinct from
# CODE-02「代码注入/动态代码执行」, and this file's own `_RISK_DESCRIPTIONS["B301"]`
# already describes it in exactly those (反序列化/deserialization) terms.
_CODE_07_TEST_IDS = frozenset({"B301"})

_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    # SECURITY: fail toward stricter, not laxer, on an unexpected/unmapped value.
    "UNDEFINED": Severity.MEDIUM,
}
_CONFIDENCE_MAP = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9, "UNDEFINED": 0.5}

# i18n (2026-07-23): bandit's own `test_name` is an internal Python plugin
# identifier (e.g. "hardcoded_tmp_directory"), not a human sentence - the UI
# needs a real Chinese title. bandit ships ~70 test IDs total; this covers the
# ones confirmed present in the pinned vendor/bandit 1.9.4 checkout's own
# `setup.cfg`/`blacklists/{calls,imports}.py`/`plugins/*.py` (read directly,
# not guessed) - same "honest about not covering every possible ID" posture
# as this file's own `_FILE_04_TEST_IDS`/`_CODE_12_TEST_IDS` comment above.
# An ID bandit adds in a future version, or one this table simply missed,
# falls back to bandit's own test_name/test_id below - never a blank title.
_TEST_ID_TITLES: dict[str, str] = {
    "B101": "使用了 assert 语句（生产环境以 -O 运行时会被优化掉，不能作为安全校验）",
    "B102": "使用了 exec()",
    "B103": "设置了过于宽松的文件权限",
    "B104": "硬编码绑定到所有网络接口（0.0.0.0）",
    "B105": "硬编码的密码字符串",
    "B106": "函数参数中硬编码的密码",
    "B107": "函数默认参数中硬编码的密码",
    "B108": "硬编码的可预测临时目录路径",
    "B110": "try/except 吞掉异常后直接 pass",
    "B112": "try/except 吞掉异常后直接 continue",
    "B113": "网络请求未设置超时时间",
    "B201": "Flask 应用开启了 debug=True",
    "B202": "tarfile 解压未校验成员路径（可能导致路径穿越）",
    "B301": "使用 pickle/dill/shelve 反序列化不可信数据",
    "B302": "使用 marshal 反序列化，存在风险",
    "B303": "使用了不安全的 MD2/MD4/MD5/SHA1 哈希算法",
    "B304": "使用了不安全的加密算法（ARC2/ARC4/Blowfish/DES/XOR 等）",
    "B305": "使用了不安全的加密模式（如 ECB）",
    "B306": "使用了不安全且已废弃的 tempfile.mktemp()",
    "B307": "使用了可能不安全的 eval()，建议改用 ast.literal_eval",
    "B308": "使用了 Django mark_safe()，可能引入 XSS 风险",
    "B310": "urllib 打开 URL 时未校验协议（file:/ 等非常规协议可能非预期）",
    "B311": "使用了非密码学安全的伪随机数生成器",
    "B312": "调用了 telnet 相关函数，telnet 协议不加密",
    "B313": "使用 cElementTree 解析不可信 XML，存在 XML 攻击风险",
    "B314": "使用 ElementTree 解析不可信 XML，存在 XML 攻击风险",
    "B315": "使用 expatreader 解析不可信 XML，存在 XML 攻击风险",
    "B316": "使用 expatbuilder 解析不可信 XML，存在 XML 攻击风险",
    "B317": "使用 xml.sax 解析不可信 XML，存在 XML 攻击风险",
    "B318": "使用 minidom 解析不可信 XML，存在 XML 攻击风险",
    "B319": "使用 pulldom 解析不可信 XML，存在 XML 攻击风险",
    "B321": "调用了 FTP 相关函数，FTP 协议不加密",
    "B323": "使用了未校验证书的 SSL 上下文（_create_unverified_context）",
    "B324": "使用了不安全的哈希算法（hashlib.md5/sha1 等）",
    "B401": "导入了 telnet 相关模块，telnet 协议不加密",
    "B402": "导入了 FTP 相关模块，FTP 协议不加密",
    "B403": "导入了 pickle/dill/shelve 模块，需关注反序列化风险",
    "B404": "导入了 subprocess 模块，需关注命令注入风险",
    "B405": "导入 xml.etree，解析不可信 XML 存在攻击风险",
    "B406": "导入 xml.sax，解析不可信 XML 存在攻击风险",
    "B407": "导入 xml.dom.expatbuilder，解析不可信 XML 存在攻击风险",
    "B408": "导入 xml.dom.minidom，解析不可信 XML 存在攻击风险",
    "B409": "导入 xml.dom.pulldom，解析不可信 XML 存在攻击风险",
    "B411": "导入 xmlrpc，解析不可信 XML 存在攻击风险",
    "B412": "导入了存在 httpoxy 类问题的 CGI 相关模块",
    "B413": "导入了已废弃且不再维护的 pyCrypto 库",
    "B415": "导入了 IPMI 相关模块，IPMI 协议不加密",
    "B501": "请求未校验 TLS 证书",
    "B502": "使用了不安全的 SSL/TLS 版本",
    "B503": "使用了不安全的 SSL 默认配置",
    "B504": "创建 SSL 上下文时未指定协议版本",
    "B505": "使用了强度不足的加密密钥",
    "B506": "使用了不安全的 yaml.load（应使用 safe_load）",
    "B507": "SSH 连接未校验主机密钥",
    "B508": "使用了不安全的 SNMP 版本",
    "B509": "使用了弱加密的 SNMP 配置",
    "B601": "调用了存在注入风险的 paramiko 命令",
    "B602": "subprocess.Popen 使用 shell=True，存在命令注入风险",
    "B603": "调用子进程时未显式设置 shell=False（需人工核查）",
    "B604": "函数调用使用了 shell=True，存在命令注入风险",
    "B605": "以 shell 方式启动进程，存在命令注入风险",
    "B606": "未经 shell 启动进程（需人工核查参数来源）",
    "B607": "以部分路径（非绝对路径）启动进程",
    "B608": "硬编码的 SQL 拼接语句，存在 SQL 注入风险",
    "B609": "Linux 命令中使用通配符，存在注入风险",
    "B610": "Django QuerySet.extra() 存在 SQL 注入风险",
    "B611": "Django RawSQL 存在 SQL 注入风险",
    "B612": "日志配置监听地址不安全",
    "B613": "检测到 Trojan Source 类隐藏字符攻击（双向控制符等）",
    "B614": "使用了不安全的 PyTorch 模型加载方式",
    "B615": "从 HuggingFace 下载模型时校验不充分",
    "B701": "Jinja2 模板关闭了自动转义，存在 XSS 风险",
    "B702": "使用了 Mako 模板，需关注其默认不转义带来的 XSS 风险",
    "B703": "Django mark_safe() 使用不当，存在 XSS 风险",
    "B704": "markupsafe Markup 使用不当，存在 XSS 风险",
}

# 安全风险描述（2026-07-24）：title 只是短标签（对应 bandit 规则名称的翻译），
# 这里针对每个 test_id 给出具体的攻击面/影响说明，避免 evidence 一栏只是把
# title 再重复一遍。与 _TEST_ID_TITLES 覆盖同一组已确认存在于 vendor/bandit
# 1.9.4 的 test_id；未收录的 ID 在 parse_output 里走通用兜底文案，不在此处
# 编造内容。
_RISK_DESCRIPTIONS: dict[str, str] = {
    "B101": (
        "assert 语句在 Python 以 -O/-OO 优化模式运行时会被整体移除，如果代码把assert 当作权限校验、"
        "输入校验等安全检查手段，这些检查会在生产环境静默失效而不报任何错误；安全校验应使用普通的 i"
        "f 判断并显式抛出异常。"
    ),
    "B102": (
        "exec() 会动态执行字符串形式的 Python 代码，如果该字符串包含任何用户输入或外部数据，攻击者"
        "可借此注入并执行任意代码。"
    ),
    "B103": (
        "该文件权限设置过于宽松（如 0o777、group/other 可写），可能允许同一主机上的其他非特权用户读"
        "取或篡改这个文件，尤其在文件包含凭据、配置或可执行代码时风险更高。"
    ),
    "B104": (
        "将服务绑定到 0.0.0.0 会让其在所有网络接口上监听，如果该服务本意只是本机调试用途，这会意外"
        "地把它暴露给同一网络内的其他主机访问。"
    ),
    "B105": (
        "代码中硬编码了密码字符串，一旦代码或版本历史泄露，该密码即随之泄露；应改为从环境变量、密钥"
        "管理服务或配置中读取。"
    ),
    "B106": (
        "函数调用的参数中硬编码了密码，与硬编码密码字符串同样的风险——凭据随源码一起暴露，应改为从密"
        "钥管理服务或环境变量注入。"
    ),
    "B107": (
        "函数的默认参数值里硬编码了密码，调用方若未显式传参就会静默使用这个泄露的默认凭据，风险与直"
        "接硬编码密码相同。"
    ),
    "B108": (
        "使用固定、可预测的 /tmp 或 /var/tmp 路径存在 TOCTOU（检查时间-使用时间）竞争风险：攻击者可"
        "在文件被创建前抢先放置符号链接或恶意文件，劫持后续的读写操作；应改用 tempfile.mkstemp() 等"
        "原子创建的安全 API。"
    ),
    "B110": (
        "try/except 捕获异常后直接 pass 会静默吞掉所有错误（包括安全相关的失败，如权限校验异常），"
        "使问题在无任何日志或告警的情况下被掩盖，增加排查和检测难度。"
    ),
    "B112": (
        "try/except 捕获异常后直接 continue，同样会静默吞掉异常并继续循环，可能掩盖安全相关的失败而"
        "不留下任何痕迹。"
    ),
    "B113": (
        "网络请求未设置超时时间，如果对端不响应，调用方会无限期挂起，容易被用于制造资源耗尽型的拒绝"
        "服务，也会拖累整体系统的可用性。"
    ),
    "B201": (
        "Flask 应用开启了 debug=True，调试模式会在报错页面暴露详细的堆栈信息和本地变量，且自带的交"
        "互式调试器（Werkzeug debugger）在某些配置下可被远程利用执行任意代码，生产环境绝不应开启。"
    ),
    "B202": (
        "tarfile 解压时未校验成员的目标路径，恶意构造的归档文件可以在条目名中包含 ../ 或绝对路径，"
        "解压时逃逸出预期目录，覆盖任意位置的文件（即 Zip Slip / 路径穿越）。"
    ),
    "B301": (
        "pickle/dill/shelve 的反序列化过程可以执行任意 Python 代码（通过自定义 __reduce__ 等机制）"
        "，对不可信来源的数据反序列化等同于让攻击者在本进程内执行任意代码。"
    ),
    "B302": (
        "marshal 是 Python 内部字节码序列化格式，未文档化且不保证版本兼容性，对不可信数据使用同样存"
        "在类似 pickle 的代码执行风险。"
    ),
    "B303": (
        "MD2/MD4/MD5/SHA1 均已被证实存在实用化的碰撞攻击，不应再用于密码存储、数字签名、完整性校验"
        "等安全场景；建议改用 SHA-256 及以上，密码存储应使用 bcrypt/scrypt/Argon2。"
    ),
    "B304": (
        "ARC2/ARC4/Blowfish/DES/XOR 等算法密钥强度不足或存在已知的密码学缺陷，无法为现代威胁模型提"
        "供有效的机密性保护；建议改用 AES-256（GCM 模式）等现代对称加密算法。"
    ),
    "B305": (
        "ECB 等不安全的加密模式对相同明文分组会产生相同密文分组，无法隐藏数据的结构性特征，存在明文"
        "模式泄露风险；建议改用 GCM/CBC（配合随机 IV）等模式。"
    ),
    "B306": (
        "tempfile.mktemp() 只预测一个尚不存在的文件名，不会原子性创建文件，在预测文件名和实际打开文"
        "件之间存在竞争窗口，攻击者可抢先创建同名文件或符号链接进行劫持；应改用 tempfile.mkstemp()"
        "。"
    ),
    "B307": (
        "eval() 会将字符串当作 Python 表达式动态求值执行，如果参数包含任何用户输入或外部数据，攻击"
        "者可借此注入执行任意代码；仅需要解析字面量时应改用 ast.literal_eval。"
    ),
    "B308": (
        "Django 的 mark_safe() 会告诉模板引擎该内容已经是安全的、无需转义，如果标记的内容包含未经清"
        "理的用户输入，会导致其在渲染时不被转义直接输出，引入存储型/反射型 XSS 风险。"
    ),
    "B310": (
        "urllib 打开 URL 时未校验协议，如果目标地址来自用户输入，攻击者可以构造 file:// 等非常规协"
        "议读取本地文件，或利用其他协议处理器产生非预期行为（SSRF 的一种变体）。"
    ),
    "B311": (
        "random 模块基于梅森旋转算法，是可预测的伪随机数生成器，如果被用于生成密码、令牌、会话 ID "
        "等安全相关的值，攻击者可能预测或还原后续输出；此类场景应改用 secrets 模块。"
    ),
    "B312": (
        "telnet 协议明文传输所有数据（包括账号密码），中间人可直接窃听或篡改会话内容；应改用 SSH 等"
        "加密协议。"
    ),
    "B313": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE（XML外部实体注入）pay"
        "load 读取服务器本地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器，或显式禁用外"
        "部实体解析。"
    ),
    "B314": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE payload 读取服务器本"
        "地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器。"
    ),
    "B315": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE payload 读取服务器本"
        "地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器。"
    ),
    "B316": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE payload 读取服务器本"
        "地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器。"
    ),
    "B317": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE payload 读取服务器本"
        "地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器。"
    ),
    "B318": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE payload 读取服务器本"
        "地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器。"
    ),
    "B319": (
        "解析不可信来源的 XML 时如果未禁用外部实体/DTD 解析，攻击者可构造 XXE payload 读取服务器本"
        "地文件或发起 SSRF 请求；应使用 defusedxml 等加固过的解析器。"
    ),
    "B321": (
        "FTP 协议明文传输账号密码和数据，中间人可直接窃听或篡改传输内容；应改用 SFTP/FTPS 等加密协"
        "议。"
    ),
    "B323": (
        "使用未校验证书的 SSL 上下文等于关闭了 TLS 的身份验证能力，无法防御中间人攻击——连接看似加密"
        "，实际上任何人都可以冒充目标服务器。"
    ),
    "B324": (
        "hashlib.md5/sha1 等算法已被证实存在实用化的碰撞攻击，不应再用于密码存储、数字签名、完整性"
        "校验等安全场景；建议改用 SHA-256 及以上（若仅用于非安全目的的缓存 key 等场景则风险较低，需"
        "结合调用位置判断）。"
    ),
    "B401": (
        "telnet 模块用于建立明文传输的会话（含账号密码），中间人可直接窃听或篡改内容；应改用 SSH 等"
        "加密协议。"
    ),
    "B402": (
        "FTP 相关模块用于建立明文传输的会话（含账号密码），中间人可直接窃听或篡改内容；应改用 SFTP/"
        "FTPS 等加密协议。"
    ),
    "B403": (
        "pickle/dill/shelve 的反序列化可以执行任意代码，导入这些模块意味着代码里可能存在对不可信数"
        "据的反序列化操作，需要人工核查具体调用点的数据来源。"
    ),
    "B404": (
        "subprocess 模块用于启动子进程，如果传给它的命令或参数拼接了用户输入且未经妥善转义/参数化，"
        "可能被注入额外命令；需要人工核查具体调用点的参数构造方式。"
    ),
    "B405": (
        "xml.etree 默认不禁用外部实体解析，对不可信 XML 输入存在 XXE 攻击风险；应使用 defusedxml 等"
        "加固过的解析器。"
    ),
    "B406": (
        "xml.sax 默认不禁用外部实体解析，对不可信 XML 输入存在 XXE 攻击风险；应使用 defusedxml 等加"
        "固过的解析器。"
    ),
    "B407": (
        "xml.dom.expatbuilder 默认不禁用外部实体解析，对不可信 XML 输入存在 XXE 攻击风险；应使用 de"
        "fusedxml 等加固过的解析器。"
    ),
    "B408": (
        "xml.dom.minidom 默认不禁用外部实体解析，对不可信 XML 输入存在 XXE 攻击风险；应使用 defused"
        "xml 等加固过的解析器。"
    ),
    "B409": (
        "xml.dom.pulldom 默认不禁用外部实体解析，对不可信 XML 输入存在 XXE 攻击风险；应使用 defused"
        "xml 等加固过的解析器。"
    ),
    "B411": (
        "xmlrpc 默认不禁用外部实体解析，对不可信 XML-RPC 请求存在 XXE 攻击风险；应使用加固过的解析"
        "方式。"
    ),
    "B412": (
        "存在 httpoxy 类问题的 CGI 相关模块会把 HTTP 请求头 Proxy 字段映射为环境变量 HTTP_PROXY，攻"
        "击者可借此让服务端后续的出站请求被重定向到攻击者控制的代理，造成请求劫持或凭据泄露。"
    ),
    "B413": (
        "pyCrypto 库自 2013 年起已不再维护，其中已知存在未修复的安全漏洞；应迁移到积极维护的 pyca/c"
        "ryptography 或 PyCryptodome。"
    ),
    "B415": (
        "IPMI 协议的部分认证机制存在已知的严重缺陷（如 RAKP 远程哈希提取漏洞），且常以明文/弱加密方"
        "式传输管理凭据，应确保仅在隔离的管理网络中使用并采用最新的加固配置。"
    ),
    "B501": (
        "发起请求时未校验 TLS 证书等于关闭了对端身份验证，无法防御中间人攻击——连接看似加密，实际上"
        "任何人都可以冒充目标服务器窃听或篡改数据。"
    ),
    "B502": (
        "使用了已被认为不安全的 SSL/TLS 协议版本（如 SSLv2/SSLv3/TLS 1.0），这些版本存在已知的协议"
        "层漏洞（如 POODLE），应强制使用 TLS 1.2 及以上。"
    ),
    "B503": (
        "使用了不安全的 SSL 默认配置（如允许弱密码套件），可能被降级攻击利用协商到较弱的加密算法，"
        "应显式指定强密码套件和最低协议版本。"
    ),
    "B504": (
        "创建 SSL 上下文时未显式指定协议版本，可能因平台/库版本差异悄悄协商到过时的不安全协议；应显"
        "式指定 TLS 1.2 及以上。"
    ),
    "B505": (
        "使用了强度不足的加密密钥长度（如 RSA < 2048 位），在现代算力下可能被暴力破解或数论攻击恢复"
        "私钥，应使用符合当前推荐强度的密钥长度。"
    ),
    "B506": (
        "yaml.load() 在未指定安全 Loader 时可以反序列化并执行任意 Python 对象构造（包括代码执行），"
        "对不可信 YAML 输入存在与 pickle 类似的任意代码执行风险；应改用 yaml.safe_load()。"
    ),
    "B507": (
        "SSH 连接未校验主机密钥（如 AutoAddPolicy），无法确认对端身份，存在被中间人攻击冒充目标主机"
        "的风险；应校验已知主机密钥或使用严格的主机密钥策略。"
    ),
    "B508": (
        "使用了不安全的 SNMP 版本（v1/v2c），其认证仅依赖明文传输的 community string，几乎没有真正"
        "的访问控制或加密保护；应升级到 SNMPv3 并启用认证与加密。"
    ),
    "B509": (
        "SNMP 配置使用了弱加密或弱认证参数，即使使用 SNMPv3 也可能因配置不当而被中间人窃听或伪造管"
        "理请求；应使用强认证协议和加密算法。"
    ),
    "B601": (
        "调用了存在命令注入风险的 paramiko 相关命令执行方法，如果拼接的命令包含用户输入且未妥善转义"
        "，攻击者可注入额外的 shell 命令在远程主机上执行。"
    ),
    "B602": (
        "subprocess.Popen 使用 shell=True 会让参数经过 shell 解释执行，如果命令字符串中拼接了用户输"
        "入且未妥善转义，攻击者可通过 shell 元字符注入并执行任意命令。"
    ),
    "B603": (
        "调用子进程时未显式指定 shell=False，需要人工核查传入的命令列表本身是否来自可信来源，避免遗"
        "漏潜在的命令注入路径。"
    ),
    "B604": (
        "以 shell=True 方式调用函数会让参数经过 shell 解释执行，如果参数拼接了用户输入且未妥善转义"
        "，攻击者可通过 shell 元字符注入并执行任意命令。"
    ),
    "B605": (
        "以 shell 方式启动进程会让命令字符串整体交给 shell 解释执行，如果字符串拼接了用户输入且未妥"
        "善转义，攻击者可注入额外命令。"
    ),
    "B606": (
        "未经 shell 启动进程本身更安全（参数不会被 shell 解释），但仍需人工核查传入的可执行文件路径"
        "和参数是否可能被外部输入影响。"
    ),
    "B607": (
        "以相对路径（非绝对路径）启动进程时，实际执行的二进制文件由当前 PATH 环境变量决定，攻击者如"
        "果能在 PATH 靠前的目录中放置同名恶意程序，就能劫持执行流程；应使用绝对路径指定可执行文件。"
    ),
    "B608": (
        "通过字符串拼接构造 SQL 语句，如果拼接的内容包含未经参数化处理的用户输入，攻击者可注入额外"
        "的 SQL 逻辑，读取/篡改/删除数据库中的任意数据，甚至在部分数据库上执行系统命令；应始终使用"
        "参数化查询或 ORM 提供的安全接口。"
    ),
    "B609": (
        "Linux 命令中使用了通配符（如 *），当命令实际以 shell 展开该通配符时，攻击者可以在目标目录"
        "下放置以 - 开头的文件名，被 shell 展开后当作命令行选项注入，篡改命令的实际行为（wildcard i"
        "njection）。"
    ),
    "B610": (
        "Django QuerySet.extra() 允许直接嵌入原始 SQL 片段，如果嵌入内容包含未经参数化处理的用户输"
        "入，存在 SQL 注入风险；应优先使用 ORM 的标准查询接口。"
    ),
    "B611": (
        "Django RawSQL() 允许直接执行原始 SQL 语句，如果语句中包含未经参数化处理的用户输入，存在 SQ"
        "L 注入风险；应优先使用 ORM 的标准查询接口或对参数使用占位符。"
    ),
    "B612": (
        "日志配置监听地址不安全（如绑定到所有网络接口且缺乏访问控制），可能允许网络上的其他主机连接"
        "日志服务并读取或注入日志内容。"
    ),
    "B613": (
        "检测到 Unicode 双向控制符等隐藏字符攻击（Trojan Source）：这类字符可以让源码在编辑器/终端"
        "里显示的逻辑与编译器/解释器实际执行的逻辑不一致，攻击者可借此在代码审查中隐藏恶意逻辑而不"
        "被发现。"
    ),
    "B614": (
        "使用了不安全的 PyTorch 模型加载方式（如未加 weights_only=True 的 torch.load），恶意构造的"
        "模型文件可以在反序列化过程中执行任意代码，等同于对不可信数据执行 pickle 反序列化。"
    ),
    "B615": (
        "从 HuggingFace 下载模型时未做充分的来源/完整性校验，如果被诱导指向被投毒或仿冒的模型仓库，"
        "加载得到的可能是被植入后门或恶意代码的模型文件。"
    ),
    "B701": (
        "Jinja2 模板关闭了自动转义（autoescape=False），如果模板中渲染了未经清理的用户输入，会导致"
        "其在 HTML 输出中不被转义直接展示，引入存储型/反射型 XSS 风险。"
    ),
    "B702": (
        "Mako 模板默认不自动转义输出内容，如果模板中渲染了未经清理的用户输入且未显式转义，会引入 XS"
        "S 风险。"
    ),
    "B703": (
        "Django mark_safe() 使用不当（标记了包含未清理用户输入的内容为安全），会导致其在模板渲染时"
        "跳过转义直接输出，引入 XSS 风险。"
    ),
    "B704": (
        "markupsafe 的 Markup 对象使用不当（包裹了未清理的用户输入），会让内容在渲染时被当作已转义"
        "的安全 HTML 直接输出，引入 XSS 风险。"
    ),
}


def _metadata(*, ruleset_digest: str, version: str) -> EngineMetadata:
    return EngineMetadata(
        name="bandit",
        version=version,
        ruleset_digest=ruleset_digest,
        capabilities=frozenset({EngineCapability.STATIC}),
    )


def _build_argv(target_dir: Path) -> list[str]:
    return ["bandit", "-r", "-f", "json", str(target_dir)]


def _test_item_id_and_category(test_id: str) -> tuple[str, DetectionCategory]:
    if test_id in _FILE_06_TEST_IDS:
        return "FILE-06", DetectionCategory.FILE_PACKAGE
    if test_id in _CODE_10_TEST_IDS:
        return "CODE-10", DetectionCategory.CODE
    if test_id in _CODE_01_TEST_IDS:
        return "CODE-01", DetectionCategory.CODE
    if test_id in _CODE_08_TEST_IDS:
        return "CODE-08", DetectionCategory.CODE
    if test_id in _CODE_02_TEST_IDS:
        return "CODE-02", DetectionCategory.CODE
    if test_id in _CODE_07_TEST_IDS:
        return "CODE-07", DetectionCategory.CODE
    # SECURITY (2026-07-27, D7): GEN-01 is the catalog's own explicit
    # "detected but unclassified" marker (企业Skill安全评估测试维度清单.xlsx,
    # D10) - NOT the raw bandit test_id. Passing the raw id through (the
    # previous behavior) silently reads as "uncovered" to any report keyed on
    # the catalog, which is strictly worse than an honest GEN-01: it hides a
    # real finding instead of merely leaving it unclassified.
    return "GEN-01", DetectionCategory.CODE


def parse_output(
    completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    payload = json.loads(
        completed.stdout
    )  # SECURITY: malformed JSON -> raises -> caller fail-closes
    if not isinstance(payload, dict) or "results" not in payload:
        raise ValueError("bandit output missing 'results' key")

    findings: list[Finding] = []
    for result in payload["results"]:
        test_id = str(result["test_id"])
        test_item_id, category = _test_item_id_and_category(test_id)
        severity = _SEVERITY_MAP.get(str(result.get("issue_severity")), Severity.MEDIUM)
        confidence = _CONFIDENCE_MAP.get(str(result.get("issue_confidence")), 0.5)
        code_snippet = str(result.get("code", ""))
        title = _TEST_ID_TITLES.get(test_id, str(result.get("test_name", test_id)))
        findings.append(
            Finding(
                rule_id=f"bandit.{test_id}",
                test_item_id=test_item_id,
                category=category,
                title=title,
                severity=severity,
                confidence=confidence,
                source_engine="bandit",
                source_capability=EngineCapability.STATIC,
                file_path=str(result.get("filename")) or None,
                start_line=result.get("line_number"),
                # SECURITY (INV-9): bandit's own "code" field is a plaintext
                # snippet from the scanned file - hash it, never forward it.
                snippet_hash=hashlib.sha256(code_snippet.encode("utf-8")).hexdigest()
                if code_snippet
                else None,
                # i18n (2026-07-23) + 安全风险描述 (2026-07-24): bandit's own
                # free-text "issue_text" is English and not a finite
                # enumerable set (it interpolates variable/module names per
                # plugin), so it can't be pre-translated via a lookup table
                # the way `title` is. `_RISK_DESCRIPTIONS` instead gives a
                # genuine, test_id-specific explanation of the underlying
                # security risk (not just a repeat of `title`) for every ID
                # `_TEST_ID_TITLES` covers; an ID neither table covers falls
                # back to the resolved title plus the bandit test_id, same
                # honest-about-the-gap posture as elsewhere in this file.
                evidence_redacted=_RISK_DESCRIPTIONS.get(test_id)
                or f"{title}（bandit {test_id}，具体风险说明请参考 bandit 官方文档）",
            )
        )
    return tuple(findings)


def make_adapter(
    *, ruleset_digest: str, version: str, timeout_s: float = DEFAULT_ENGINE_TIMEOUT_S
) -> SubprocessEngineAdapter:
    """`ruleset_digest`/`version` come from the pinned vendored commit
    (coding spec: 'name@version#ruleset_digest 来自 pin 的镜像 digest') - the
    caller (wherever engines are wired up) is responsible for deriving these
    from `vendor/engines.lock.yaml`, not this module."""
    return SubprocessEngineAdapter(
        metadata=_metadata(ruleset_digest=ruleset_digest, version=version),
        build_argv=_build_argv,
        parse_output=parse_output,
        treat_nonzero_exit_as_error=False,
        timeout_s=timeout_s,
    )
