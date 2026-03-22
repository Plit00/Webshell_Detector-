#!/usr/bin/env python3
"""
WebShell Detector
2026.03.10 dhkim
"""

import os, re, sys, json, stat, hashlib, argparse
from datetime import datetime
from pathlib import Path

SEVERITY_COLOR = {
    'CRITICAL': '\033[91m', 'HIGH': '\033[93m', 'MEDIUM': '\033[94m',
    'LOW': '\033[96m', 'INFO': '\033[92m', 'RESET': '\033[0m',
}
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

def colorize(text, level):
    return f"{SEVERITY_COLOR.get(level,'')}{text}{SEVERITY_COLOR['RESET']}"

def md5_file(path):
    h = hashlib.md5()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''): h.update(chunk)
        return h.hexdigest()
    except: return 'N/A'

def is_md5_filename(name):
    return bool(re.fullmatch(r'[a-f0-9]{32}', Path(name).stem, re.IGNORECASE))

def is_world_writable(path):
    try: return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except: return False

def file_mtime_str(path):
    try: return datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
    except: return 'N/A'

def read_file_safe(path, max_bytes=1024*1024):
    try:
        size = os.path.getsize(path)
        if size == 0: return None, '빈 파일'
        with open(path, 'rb') as f:
            raw = f.read(min(size, max_bytes))
        if raw.count(b'\x00') / len(raw) > 0.1: return None, '바이너리 파일'
        return raw.decode('utf-8', errors='replace'), None
    except PermissionError: return None, '권한 없음'
    except Exception as e: return None, str(e)

# ══════════════════════════════════════════════════════════════════
# PHP 패턴
# ══════════════════════════════════════════════════════════════════
PHP_PATTERNS = [
    (r'c99shell',                                                         'CRITICAL', '[PHP] c99shell 웹셸'),
    (r'r57shell',                                                         'CRITICAL', '[PHP] r57shell 웹셸'),
    (r'b374k',                                                            'CRITICAL', '[PHP] b374k 웹셸'),
    (r'wso\s*(shell|2\.)',                                                'CRITICAL', '[PHP] WSO 웹셸'),
    (r'FilesMan',                                                         'CRITICAL', '[PHP] FilesMan 웹셸'),
    (r'indoxploit',                                                       'CRITICAL', '[PHP] IndoXploit 웹셸'),
    (r'alfa\s*shell',                                                     'CRITICAL', '[PHP] Alfa 웹셸'),
    (r'ghost\s*shell',                                                    'CRITICAL', '[PHP] Ghost 웹셸'),
    (r'webshell',                                                         'HIGH',     '[PHP] webshell 키워드'),
    # 외부입력 변수
    (r'\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*["\']?(cmd|command|exec|execute|run|shell|c|e|x|do|act|func|code|payload|pass|passwd|p|q|ip|host)\s*["\']?\s*\]',
                                                                          'CRITICAL', '[PHP] 외부입력 cmd/exec 변수'),
    # 명령실행 + 외부입력
    (r'(system|exec|passthru|shell_exec|popen|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                                                                          'CRITICAL', '[PHP] 명령실행함수+외부입력'),
    (r'(system|exec|passthru|shell_exec|popen|pcntl_exec)\s*\(\s*\$\w+', 'HIGH',     '[PHP] 명령실행함수+변수'),
    (r'proc_open\s*\(',                                                   'HIGH',     '[PHP] proc_open'),
    # 백틱
    (r'`\s*\$_(GET|POST|REQUEST|COOKIE)',                                 'CRITICAL', '[PHP] 백틱+외부입력'),
    (r'`[^`]*\$\w+[^`]*`',                                               'HIGH',     '[PHP] 백틱 명령실행'),
    # eval 난독화
    (r'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',                         'CRITICAL', '[PHP] eval+외부입력'),
    (r'eval\s*\(\s*base64_decode',                                        'CRITICAL', '[PHP] eval+base64_decode'),
    (r'eval\s*\(\s*gzinflate',                                            'CRITICAL', '[PHP] eval+gzinflate'),
    (r'eval\s*\(\s*gzuncompress',                                         'CRITICAL', '[PHP] eval+gzuncompress'),
    (r'eval\s*\(\s*gzdecode',                                             'CRITICAL', '[PHP] eval+gzdecode'),
    (r'eval\s*\(\s*str_rot13',                                            'CRITICAL', '[PHP] eval+str_rot13'),
    (r'eval\s*\(\s*strrev',                                               'CRITICAL', '[PHP] eval+strrev'),
    (r'eval\s*\(\s*hex2bin',                                              'CRITICAL', '[PHP] eval+hex2bin'),
    (r'eval\s*\(\s*pack\s*\(',                                            'CRITICAL', '[PHP] eval+pack'),
    (r'eval\s*\(\s*\w+\s*\(\s*\w+\s*\(',                                 'CRITICAL', '[PHP] 다중 난독화 eval'),
    (r'eval\s*\(\s*str_replace',                                          'HIGH',     '[PHP] eval+str_replace'),
    # assert
    (r'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',                       'CRITICAL', '[PHP] assert+외부입력'),
    (r'assert\s*\(\s*base64_decode',                                      'CRITICAL', '[PHP] assert+base64_decode'),
    (r'assert\s*\(\s*\$\w+\s*\)',                                         'HIGH',     '[PHP] assert+변수'),
    # preg_replace /e
    (r'preg_replace\s*\(.+/e["\'\s,]',                                   'CRITICAL', '[PHP] preg_replace /e 코드실행'),
    # 가변함수
    (r'\$\w+\s*=\s*["\'\s]*(system|exec|passthru|shell_exec|assert|eval)\s*["\']',
                                                                          'CRITICAL', '[PHP] 가변함수 명령실행 저장'),
    (r'call_user_func\s*\(\s*\$_(GET|POST|REQUEST)',                      'CRITICAL', '[PHP] call_user_func+외부입력'),
    (r'call_user_func_array\s*\(\s*\$',                                   'HIGH',     '[PHP] call_user_func_array+변수'),
    (r'array_map\s*\(\s*["\']?(system|exec|passthru|shell_exec)',         'CRITICAL', '[PHP] array_map+명령실행'),
    (r'create_function\s*\(',                                             'CRITICAL', '[PHP] create_function 코드실행'),
    (r'usort\s*\(.+\$_(GET|POST|REQUEST)',                                'HIGH',     '[PHP] usort+외부입력'),
    # 리버스셸
    (r'fsockopen\s*\(.+,\s*\d+',                                         'CRITICAL', '[PHP] fsockopen 리버스셸'),
    (r'bash\s+-i\s+>&',                                                   'CRITICAL', '[PHP] bash 리버스셸'),
    # 파일 드롭
    (r'file_put_contents\s*\(.+\$_(GET|POST|REQUEST)',                    'CRITICAL', '[PHP] 외부입력으로 파일 쓰기'),
    (r'file_put_contents\s*\(.+base64_decode',                           'CRITICAL', '[PHP] base64 디코딩 후 파일 쓰기'),
    (r'file_get_contents\s*\(\s*["\']https?://',                         'HIGH',     '[PHP] 원격 파일 다운로드'),
    (r'fwrite\s*\(.+\$_(GET|POST|REQUEST)',                               'HIGH',     '[PHP] fwrite+외부입력'),
    (r'fputs\s*\(.+\$_(GET|POST|REQUEST)',                                'HIGH',     '[PHP] fputs+외부입력'),
    (r'move_uploaded_file',                                               'MEDIUM',   '[PHP] 파일 업로드 처리'),
    # .htaccess 악용
    (r'SetHandler\s+application/x-httpd-php',                            'CRITICAL', '[HTACCESS] PHP핸들러 설정'),
    (r'AddType\s+application/x-httpd-php',                               'CRITICAL', '[HTACCESS] PHP타입 설정'),
    (r'php_value\s+auto_prepend_file',                                   'CRITICAL', '[HTACCESS] auto_prepend_file'),
    (r'php_value\s+auto_append_file',                                    'CRITICAL', '[HTACCESS] auto_append_file'),
    # 난독화
    (r'base64_decode\s*\(\s*["\'][A-Za-z0-9+/]{50,}',                   'HIGH',     '[PHP] 긴 base64 문자열'),
    (r'(chr\s*\(\s*\d+\s*\)\.){3,}',                                     'HIGH',     '[PHP] chr() 연결 난독화'),
    # 정보 수집
    (r'phpinfo\s*\(\s*\)',                                                'MEDIUM',   '[PHP] phpinfo 노출'),
    (r'posix_getpwuid\s*\(',                                              'MEDIUM',   '[PHP] POSIX 유저 정보 수집'),
    (r'chmod\s*\(\s*.+,\s*0?777\s*\)',                                   'HIGH',     '[PHP] chmod 777'),
    (r'md5\s*\(\s*\$_(GET|POST|REQUEST)',                                 'HIGH',     '[PHP] md5+외부입력 인증'),
    (r'strcmp\s*\(\s*\$_(GET|POST|REQUEST)',                              'HIGH',     '[PHP] strcmp 인증우회'),
    (r'phpinfo\s*\(\s*\)',                                                'MEDIUM',   '[PHP] phpinfo 노출'),
]

# ══════════════════════════════════════════════════════════════════
# JSP 패턴
# ══════════════════════════════════════════════════════════════════
JSP_PATTERNS = [
    (r'jspspy',                                                           'CRITICAL', '[JSP] JspSpy 웹셸'),
    (r'Behinder',                                                         'CRITICAL', '[JSP] Behinder 웹셸'),
    (r'Godzilla',                                                         'CRITICAL', '[JSP] Godzilla 웹셸'),
    (r'antSword',                                                         'CRITICAL', '[JSP] AntSword 에이전트'),
    (r'javax\.crypto\.Cipher',                                           'HIGH',     '[JSP] 암호화 통신 웹셸 의심'),
    (r'Runtime\.getRuntime\(\)\.exec\s*\(',                              'CRITICAL', '[JSP] Runtime.exec() 명령실행'),
    (r'ProcessBuilder',                                                   'HIGH',     '[JSP] ProcessBuilder 명령실행'),
    (r'request\.getParameter\s*\(\s*["\']?(cmd|command|exec|shell|run|c|e)\s*["\']?\s*\)',
                                                                          'CRITICAL', '[JSP] request.getParameter cmd/exec'),
    (r'\.exec\s*\(\s*request\.getParameter',                             'CRITICAL', '[JSP] exec+request.getParameter'),
    (r'Class\.forName\s*\(\s*request\.getParameter',                     'CRITICAL', '[JSP] Class.forName+외부입력'),
    (r'defineClass\s*\(',                                                 'CRITICAL', '[JSP] defineClass 동적 클래스 로드'),
    (r'\.invoke\s*\(.+request\.getParameter',                            'CRITICAL', '[JSP] invoke+외부입력'),
    (r'FileOutputStream\s*\(.+request\.getParameter',                    'CRITICAL', '[JSP] 외부입력으로 파일 쓰기'),
    (r'new\s+File\s*\(\s*request\.getParameter',                        'HIGH',     '[JSP] 외부입력 파일 경로'),
    (r'Base64\.decode',                                                   'HIGH',     '[JSP] Base64 디코딩'),
    (r'java\.net\.Socket\s*\(\s*request\.getParameter',                  'CRITICAL', '[JSP] Socket+외부입력 리버스셸'),
    (r'new\s+Socket\s*\(\s*["\'][0-9.]+["\']',                          'HIGH',     '[JSP] 하드코딩 IP 소켓 연결'),
    (r'System\.getProperties\(\)',                                        'MEDIUM',   '[JSP] 시스템 속성 수집'),
    (r'ClassLoader',                                                      'HIGH',     '[JSP] ClassLoader 사용'),
]

# ══════════════════════════════════════════════════════════════════
# ASP / ASPX 패턴
# ══════════════════════════════════════════════════════════════════
ASP_PATTERNS = [
    (r'China\s*Chopper',                                                  'CRITICAL', '[ASP] China Chopper 웹셸'),
    (r'eval\s*request\s*\(',                                              'CRITICAL', '[ASP] eval request 코드실행'),
    (r'execute\s*\(\s*request',                                           'CRITICAL', '[ASP] execute(request) 코드실행'),
    (r'wscript\.shell',                                                   'CRITICAL', '[ASP] WScript.Shell 명령실행'),
    (r'shell\.application',                                               'CRITICAL', '[ASP] Shell.Application'),
    (r'CreateObject\s*\(\s*["\']WScript\.Shell["\']',                   'CRITICAL', '[ASP] CreateObject WScript.Shell'),
    (r'CreateObject\s*\(\s*["\']ADODB\.Stream["\']',                    'HIGH',     '[ASP] ADODB.Stream 파일 쓰기'),
    (r'\.Run\s*\(\s*Request',                                            'CRITICAL', '[ASP] .Run(Request) 명령실행'),
    (r'\.Exec\s*\(\s*Request',                                           'CRITICAL', '[ASP] .Exec(Request) 명령실행'),
    (r'Request\s*\(\s*["\']?(cmd|command|exec|shell|run)\s*["\']?\s*\)', 'CRITICAL', '[ASP] Request cmd/exec 파라미터'),
    (r'Request\.QueryString\s*\(\s*["\']?(cmd|exec)',                    'CRITICAL', '[ASP] QueryString cmd/exec'),
    (r'Request\.Form\s*\(\s*["\']?(cmd|exec)',                           'CRITICAL', '[ASP] Form cmd/exec'),
    (r'FileSystemObject',                                                 'MEDIUM',   '[ASP] FileSystemObject'),
    (r'\.Write\s*\(\s*Request',                                          'HIGH',     '[ASP] Write(Request) 파일 쓰기'),
    (r'Chr\s*\(\s*\d+\s*\)\s*&\s*Chr\s*\(',                            'HIGH',     '[ASP] Chr() 연결 난독화'),
    # cmd.exe 직접 실행
    (r'cmd\.exe\s*/c',                                                   'CRITICAL', '[ASP] cmd.exe /c 명령실행'),
    (r'\.Run\s*\(\s*["\']?cmd',                                         'CRITICAL', '[ASP] .Run cmd 명령실행'),
    (r'\.Run\s*\(.+Request\.',                                           'CRITICAL', '[ASP] .Run+Request 명령실행'),
    (r'Request\.Form\s*\(\s*["\']?\.?CMD',                              'CRITICAL', '[ASP] Request.Form CMD 파라미터'),
    # WSCRIPT 악용
    (r'WSCRIPT\.SHELL',                                                  'CRITICAL', '[ASP] WSCRIPT.SHELL'),
    (r'WSCRIPT\.NETWORK',                                                'HIGH',     '[ASP] WSCRIPT.NETWORK'),
    (r'Server\.CreateObject\s*\(\s*["\']WSCRIPT',                       'CRITICAL', '[ASP] CreateObject WSCRIPT'),
    # 임시파일 생성 후 실행 패턴
    (r'GetTempName\s*\(\s*\)',                                           'HIGH',     '[ASP] GetTempName 임시파일 생성'),
    (r'OpenTextFile\s*\(',                                               'MEDIUM',   '[ASP] OpenTextFile'),
    (r'DeleteFile\s*\(',                                                 'MEDIUM',   '[ASP] DeleteFile (흔적 삭제 의심)'),
    # 에러 무시 (은폐 시도)
    (r'On\s+Error\s+Resume\s+Next',                                     'MEDIUM',   '[ASP] On Error Resume Next (에러 은폐)'),
    # 서버 정보 수집
    (r'Request\.ServerVariables\s*\(\s*["\']URL',                       'LOW',      '[ASP] ServerVariables URL 수집'),
    (r'Server\.HTMLEncode\s*\(',                                         'LOW',      '[ASP] HTMLEncode 출력'),
]

# ══════════════════════════════════════════════════════════════════
# Python 웹셸 패턴
# ══════════════════════════════════════════════════════════════════
PYTHON_PATTERNS = [
    (r'os\.system\s*\(\s*request\.',                                      'CRITICAL', '[PY] os.system+request'),
    (r'os\.popen\s*\(\s*request\.',                                       'CRITICAL', '[PY] os.popen+request'),
    (r'subprocess\.(call|run|Popen)\s*\(.*(request\.|input\()',           'CRITICAL', '[PY] subprocess+외부입력'),
    (r'commands\.getoutput\s*\(',                                         'HIGH',     '[PY] commands.getoutput'),
    (r'__import__\s*\(\s*["\']os["\']',                                  'HIGH',     '[PY] __import__(os)'),
    (r'eval\s*\(\s*request\.',                                           'CRITICAL', '[PY] eval+request'),
    (r'exec\s*\(\s*request\.',                                           'CRITICAL', '[PY] exec+request'),
    (r'eval\s*\(\s*base64\.b64decode',                                   'CRITICAL', '[PY] eval+base64'),
    (r'exec\s*\(\s*base64\.b64decode',                                   'CRITICAL', '[PY] exec+base64'),
    (r'socket\.connect\s*\(\s*\(',                                       'CRITICAL', '[PY] socket.connect 리버스셸'),
    (r'pty\.spawn\s*\(',                                                 'CRITICAL', '[PY] pty.spawn'),
    (r'os\.dup2\s*\(',                                                   'CRITICAL', '[PY] os.dup2 리버스셸'),
    (r'request\.args\.get\s*\(\s*["\']?(cmd|exec|command)',             'CRITICAL', '[PY] Flask request.args cmd/exec'),
    (r'request\.form\.get\s*\(\s*["\']?(cmd|exec|command)',             'CRITICAL', '[PY] Flask request.form cmd/exec'),
]

# ══════════════════════════════════════════════════════════════════
# Perl 패턴
# ══════════════════════════════════════════════════════════════════
PERL_PATTERNS = [
    (r'system\s*\(\s*\$ENV\{',                                           'CRITICAL', '[PERL] system+ENV'),
    (r'system\s*\(\s*param\s*\(',                                        'CRITICAL', '[PERL] system+CGI param'),
    (r'exec\s*\(\s*param\s*\(',                                          'CRITICAL', '[PERL] exec+CGI param'),
    (r'`\s*\$ENV\{',                                                     'CRITICAL', '[PERL] 백틱+ENV'),
    (r'`\s*param\s*\(',                                                  'CRITICAL', '[PERL] 백틱+CGI param'),
    (r'eval\s*\(\s*decode_base64',                                       'CRITICAL', '[PERL] eval+base64'),
    (r'use\s+Socket;.*connect\s*\(',                                     'CRITICAL', '[PERL] Socket 리버스셸'),
    (r'CGI::param\s*\(\s*["\']?(cmd|exec|command)',                     'CRITICAL', '[PERL] CGI param cmd/exec'),
    (r'\$shell\s*=',                                                     'HIGH',     '[PERL] $shell 변수'),
]

# ══════════════════════════════════════════════════════════════════
# Ruby 패턴
# ══════════════════════════════════════════════════════════════════
RUBY_PATTERNS = [
    (r'system\s*\(\s*params\[',                                          'CRITICAL', '[RUBY] system+params'),
    (r'exec\s*\(\s*params\[',                                            'CRITICAL', '[RUBY] exec+params'),
    (r'IO\.popen\s*\(\s*params\[',                                       'CRITICAL', '[RUBY] IO.popen+params'),
    (r'eval\s*\(\s*params\[',                                            'CRITICAL', '[RUBY] eval+params'),
    (r'eval\s*\(\s*Base64\.decode64',                                    'CRITICAL', '[RUBY] eval+base64'),
    (r'require\s+["\']socket["\']',                                      'HIGH',     '[RUBY] socket require'),
    (r'Kernel\.exec\s*\(',                                               'HIGH',     '[RUBY] Kernel.exec'),
    (r'Open3\.(popen|capture)',                                          'HIGH',     '[RUBY] Open3 명령실행'),
]

# ══════════════════════════════════════════════════════════════════
# Shell Script 악성 패턴
# ══════════════════════════════════════════════════════════════════
SHELL_PATTERNS = [
    # 리버스셸
    (r'bash\s+-i\s+>&\s*/dev/tcp/',                                      'CRITICAL', '[SH] bash TCP 리버스셸'),
    (r'bash\s+-i\s+>&\s*/dev/udp/',                                      'CRITICAL', '[SH] bash UDP 리버스셸'),
    (r'nc\s+.*\s+-e\s+(/bin/sh|/bin/bash)',                             'CRITICAL', '[SH] netcat 리버스셸'),
    (r'ncat\s+.*\s+-e\s+',                                               'CRITICAL', '[SH] ncat 리버스셸'),
    (r'python\s+-c\s+["\']import\s+socket',                             'CRITICAL', '[SH] Python 소켓 리버스셸'),
    (r'perl\s+-e\s+["\']use\s+Socket',                                  'CRITICAL', '[SH] Perl 소켓 리버스셸'),
    (r'ruby\s+-rsocket',                                                 'CRITICAL', '[SH] Ruby 소켓 리버스셸'),
    (r'socat\s+.*exec:',                                                 'CRITICAL', '[SH] socat 리버스셸'),
    # 다운로드 후 실행
    (r'curl\s+https?://\S+\s*\|\s*(bash|sh|perl|python)',               'CRITICAL', '[SH] curl pipe 실행'),
    (r'wget\s+-O-\s+https?://\S+\s*\|\s*(bash|sh)',                     'CRITICAL', '[SH] wget pipe 실행'),
    (r'(wget|curl)\s+https?://\S+.*&&\s*(chmod|bash|sh|perl|python)',   'CRITICAL', '[SH] 다운로드 후 실행'),
    # cron 백도어
    (r'crontab\s+-[el]',                                                 'HIGH',     '[SH] crontab 수정'),
    (r'echo\s+.+>>\s*/etc/cron',                                        'CRITICAL', '[SH] /etc/cron 직접 수정'),
    (r'\*\s+\*\s+\*\s+\*\s+\*.+(wget|curl|nc|bash)',                   'CRITICAL', '[SH] cron 백도어'),
    # 권한 상승
    (r'chmod\s+(4755|777|u\+s)\s+',                                     'HIGH',     '[SH] SUID 또는 chmod 777'),
    (r'echo\s+.+>>\s*/etc/sudoers',                                     'CRITICAL', '[SH] /etc/sudoers 수정'),
    # 계정 백도어
    (r'useradd\s+.*-p\s+',                                               'CRITICAL', '[SH] 패스워드 포함 계정 생성'),
    (r'echo\s+.+>>\s*/etc/passwd',                                      'CRITICAL', '[SH] /etc/passwd 직접 수정'),
    # SSH 백도어
    (r'echo\s+.+>>\s*.*authorized_keys',                                'CRITICAL', '[SH] authorized_keys 수정'),
    # 로그 삭제
    (r'(rm|shred|truncate)\s+.*(auth\.log|syslog|messages|secure|access_log|bash_history)',
                                                                         'CRITICAL', '[SH] 로그 파일 삭제'),
    (r'history\s+-c',                                                    'HIGH',     '[SH] 히스토리 삭제'),
    (r'unset\s+HISTFILE',                                                'HIGH',     '[SH] HISTFILE 비활성화'),
    (r'export\s+HISTSIZE=0',                                             'HIGH',     '[SH] HISTSIZE=0'),
    # 민감 파일
    (r'cat\s+/etc/shadow',                                               'CRITICAL', '[SH] /etc/shadow 읽기'),
    (r'cat\s+/etc/passwd',                                               'HIGH',     '[SH] /etc/passwd 읽기'),
    (r'find\s+/\s+-perm\s+-4000',                                       'HIGH',     '[SH] SUID 파일 탐색'),
]

# ══════════════════════════════════════════════════════════════════
# 공통 패턴 (언어 무관)
# ══════════════════════════════════════════════════════════════════
COMMON_PATTERNS = [
    (r'/dev/tcp/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d+',  'CRITICAL', '[공통] /dev/tcp IP:PORT 리버스셸'),
    (r'/etc/passwd',                                                      'CRITICAL', '[공통] /etc/passwd 참조'),
    (r'/etc/shadow',                                                      'CRITICAL', '[공통] /etc/shadow 참조'),
    (r'\.ssh/id_rsa',                                                    'CRITICAL', '[공통] SSH 개인키 접근'),
    (r'\.ssh/authorized_keys',                                           'CRITICAL', '[공통] authorized_keys 접근'),
    (r'/proc/self/environ',                                               'HIGH',     '[공통] /proc/self/environ 접근'),
    (r'@\$_(GET|POST|REQUEST|COOKIE)',                                   'HIGH',     '[공통] @ 에러억제+외부입력'),
    (r'(cmd|command|exec)\s*=\s*\$_(GET|POST|REQUEST)',                  'CRITICAL', '[공통] cmd/exec 변수 할당'),
]

# 확장자 → 패턴 매핑
EXT_PATTERN_MAP = {
    '.php':   PHP_PATTERNS + COMMON_PATTERNS,
    '.php3':  PHP_PATTERNS + COMMON_PATTERNS,
    '.php4':  PHP_PATTERNS + COMMON_PATTERNS,
    '.php5':  PHP_PATTERNS + COMMON_PATTERNS,
    '.php7':  PHP_PATTERNS + COMMON_PATTERNS,
    '.phtml': PHP_PATTERNS + COMMON_PATTERNS,
    '.phar':  PHP_PATTERNS + COMMON_PATTERNS,
    '.shtml': PHP_PATTERNS + COMMON_PATTERNS,
    '.jsp':   JSP_PATTERNS + COMMON_PATTERNS,
    '.jspx':  JSP_PATTERNS + COMMON_PATTERNS,
    '.asp':   ASP_PATTERNS + COMMON_PATTERNS,
    '.aspx':  ASP_PATTERNS + COMMON_PATTERNS,
    '.asa':   ASP_PATTERNS + COMMON_PATTERNS,
    '.vbs':   ASP_PATTERNS + COMMON_PATTERNS,
    '.cdx':   ASP_PATTERNS + COMMON_PATTERNS,
    '.asa':   ASP_PATTERNS + COMMON_PATTERNS,
    '.py':    PYTHON_PATTERNS + COMMON_PATTERNS,
    '.pl':    PERL_PATTERNS + COMMON_PATTERNS,
    '.pm':    PERL_PATTERNS + COMMON_PATTERNS,
    '.rb':    RUBY_PATTERNS + COMMON_PATTERNS,
    '.sh':    SHELL_PATTERNS + COMMON_PATTERNS,
    '.bash':  SHELL_PATTERNS + COMMON_PATTERNS,
    '.zsh':   SHELL_PATTERNS + COMMON_PATTERNS,
    '':       PHP_PATTERNS + JSP_PATTERNS + SHELL_PATTERNS + COMMON_PATTERNS,
}

ALL_PATTERNS = (PHP_PATTERNS + JSP_PATTERNS + ASP_PATTERNS + PYTHON_PATTERNS +
                PERL_PATTERNS + RUBY_PATTERNS + SHELL_PATTERNS + COMMON_PATTERNS)

SUSPICIOUS_FILENAME_KEYWORDS = [
    'shell', 'c99', 'r57', 'wso', 'b374k', 'hack', 'cmd', 'exec',
    'backdoor', 'exploit', 'payload', 'reverse', 'bind', 'inject',
    'upload', 'drop', 'agent', 'bypass', 'webshell', 'chopper',
]

# ══════════════════════════════════════════════════════════════════
# 스캔 로직
# ══════════════════════════════════════════════════════════════════
def scan_content(content, patterns):
    findings = []
    for pattern, severity, desc in patterns:
        try:
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
        except re.error:
            continue
        if matches:
            line_no = content[:matches[0].start()].count('\n') + 1
            findings.append({
                'severity': severity,
                'description': desc,
                'line': line_no,
                'match': matches[0].group()[:100].replace('\n', '\\n'),
                'count': len(matches),
            })
    return findings

def scan_file(path: Path):
    result = {
        'path': str(path),
        'md5': '',
        'mtime': file_mtime_str(path),
        'size': 0,
        'world_writable': is_world_writable(path),
        'md5_filename': is_md5_filename(path.name),
        'no_extension': path.suffix == '',
        'suspicious_filename': any(k in path.name.lower() for k in SUSPICIOUS_FILENAME_KEYWORDS),
        'findings': [],
        'error': None,
    }
    try: result['size'] = os.path.getsize(path)
    except: pass

    content, err = read_file_safe(path)
    if err:
        result['error'] = err
        return result

    ext = path.suffix.lower()
    patterns = EXT_PATTERN_MAP.get(ext, ALL_PATTERNS)
    result['findings'] = scan_content(content, patterns)
    result['md5'] = md5_file(path)
    return result

def top_severity(findings):
    if not findings: return 'INFO'
    return min(findings, key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))['severity']

def walk_and_scan(base_dirs, max_file_size=10*1024*1024):
    results, scanned, skipped, found_count = [], 0, 0, 0
    skip_dirs = {'proc', 'sys', 'dev', '.git', 'node_modules', '__pycache__', '.svn'}

    def progress(fpath):
        fc = ('\033[91m' + str(found_count) + '\033[0m') if found_count else str(found_count)
        path_str = str(fpath)[-55:]
        sys.stdout.write(f"\r  검사: {scanned:>6}  발견: {fc}  스킵: {skipped:>4}  |  {path_str:<55}")
        sys.stdout.flush()

    for base in base_dirs:
        base = Path(base)
        if not base.exists():
            print(f"  [WARN] 경로 없음: {base}")
            continue
        print(f"\n\033[92m  ▶ 디렉터리: {base}\033[0m")
        for root, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                fpath = Path(root) / fname
                try:
                    if not fpath.is_file(): continue
                    size = fpath.stat().st_size
                    if size > max_file_size:
                        skipped += 1
                        progress(fpath)
                        continue
                    r = scan_file(fpath)
                    scanned += 1
                    if r['findings'] or r['md5_filename'] or r['suspicious_filename'] or r['world_writable']:
                        results.append(r)
                        found_count += 1
                        sys.stdout.write('\r' + ' ' * 100 + '\r')
                        sev = top_severity(r['findings'])
                        sev_color = {'CRITICAL':'\033[91m','HIGH':'\033[93m','MEDIUM':'\033[94m'}.get(sev,'')
                        print(f"  {sev_color}[{sev}]\033[0m {r['path']}")
                        for f in sorted(r['findings'], key=lambda x: SEVERITY_ORDER.get(x['severity'], 9))[:3]:
                            sc = {'CRITICAL':'\033[91m','HIGH':'\033[93m','MEDIUM':'\033[94m'}.get(f['severity'],'')
                            print(f"        └ {sc}{f['severity']}\033[0m | {f['description']} (line {f['line']})")
                    progress(fpath)
                except: skipped += 1

    sys.stdout.write('\r' + ' ' * 120 + '\r')
    print(f"\n\033[92m  완료 ▶ 검사: {scanned}  발견: {found_count}  스킵: {skipped}\033[0m")
    return results, scanned, skipped

# ══════════════════════════════════════════════════════════════════
# 리포트
# ══════════════════════════════════════════════════════════════════

def print_report(results, scanned, skipped, output_json=None):
    sev_count = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for f in r['findings']:
            sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1

    print("\n" + "="*70)
    print(colorize("  WebShell Detector v2.0 - 탐지 결과", 'CRITICAL'))
    print("="*70)
    print(f"  스캔 파일 수  : {scanned}")
    print(f"  스킵 파일 수  : {skipped}")
    print(f"  의심 파일 수  : {len(results)}")
    print(f"  스캔 시각     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("  심각도별 요약:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if sev_count.get(sev, 0):
            print(f"    {colorize(f'{sev:<10}', sev)}: {sev_count[sev]}건")
    print("="*70)

    results.sort(key=lambda r: SEVERITY_ORDER.get(top_severity(r['findings']), 4))

    for r in results:
        sev = top_severity(r['findings'])
        print(f"\n{'─'*70}")
        print(f"  파일   : {colorize(r['path'], sev)}")
        print(f"  심각도 : {colorize(sev, sev)}")
        print(f"  수정일 : {r['mtime']}   크기: {r['size']} bytes")
        print(f"  MD5    : {r['md5']}")

        flags = []
        if r['md5_filename']:        flags.append(colorize('MD5파일명', 'HIGH'))
        if r['no_extension']:        flags.append(colorize('확장자없음', 'HIGH'))
        if r['suspicious_filename']: flags.append(colorize('의심파일명', 'MEDIUM'))
        if r['world_writable']:      flags.append(colorize('전체쓰기가능', 'HIGH'))
        if flags: print(f"  플래그 : {' | '.join(flags)}")
        if r['error']: print(f"  오류   : {r['error']}")

        if r['findings']:
            print(f"  탐지 패턴 ({len(r['findings'])}건):")
            for f in sorted(r['findings'], key=lambda x: SEVERITY_ORDER.get(x['severity'], 9)):
                print(f"    [{colorize(f['severity'][:4], f['severity'])}] Line {f['line']:>5} | {f['description']}")
                print(f"           → {repr(f['match'][:80])}")
                if f['count'] > 1:
                    print(f"             (총 {f['count']}회 발견)")

    print(f"\n{'='*70}")
    c = sev_count.get('CRITICAL', 0)
    if c: print(colorize(f"  ⚠️  CRITICAL {c}건 발견! 즉시 조치 필요!", 'CRITICAL'))
    else: print(colorize("  ✅ CRITICAL 위협 없음", 'INFO'))
    print("="*70)

    if output_json:
        with open(output_json, 'w', encoding='utf-8') as f:
            json.dump({'scan_time': datetime.now().isoformat(), 'scanned': scanned,
                       'skipped': skipped, 'severity_summary': sev_count, 'results': results},
                      f, ensure_ascii=False, indent=2)
        print(f"\n  JSON 저장: {output_json}")

# ══════════════════════════════════════════════════════════════════
# 메인
# ══════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description='WebShell Detector - PHP/JSP/ASP/PY/PERL/RUBY/SH 웹셸 탐지')
    parser.add_argument('--dirs', nargs='+', required=True, help='스캔할 디렉터리 경로')
    parser.add_argument('--json', metavar='FILE', help='결과 JSON 저장 (미지정시 자동 생성)')
    parser.add_argument('--max-size', type=int, default=10, help='최대 파일 크기 MB (기본: 10)')
    args = parser.parse_args()

    # JSON 저장 경로 자동 생성 (미지정시)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_json = args.json if args.json else f"webshell_result_{ts}.json"

    print(colorize("\n[WebShell Detector v2.0] 스캔 시작", 'INFO'))
    print(f"  대상: {', '.join(args.dirs)}")
    print(f"  최대 파일 크기: {args.max_size}MB")
    print(f"  결과 저장 경로: {output_json}\n")

    results, scanned, skipped = walk_and_scan(args.dirs, max_file_size=args.max_size * 1024 * 1024)
    print_report(results, scanned, skipped, output_json=output_json)

if __name__ == '__main__':
    main()
