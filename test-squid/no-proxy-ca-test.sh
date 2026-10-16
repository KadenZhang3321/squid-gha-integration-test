#!/usr/bin/env bash
# =============================================================================
# no-proxy-ca-test.sh —— no_proxy 直连 × CA 注入变量组 矩阵测试
#
# 背景：平台向 runner / 工作负载 pod 注入一组 CA 环境变量，全部指向
#       /etc/squid-ca/squid-ca.pem（squid MITM CA）。按工具实现分三类语义：
#
#   语义                          变量                            工具
#   ----------------------------------------------------------------
#   排他 CAfile（信任集=仅此文件） CURL_CA_BUNDLE                  curl
#                                 REQUESTS_CA_BUNDLE              requests/httpx
#                                 GIT_SSL_CAINFO                  git
#                                 PIP_CERT                        pip
#   库级 default-paths            SSL_CERT_FILE                   OpenSSL 系
#     （file∪dir，dir 仍生效）                                    (s_client 等)
#   追加（不替换内置 Mozilla 根）  NODE_EXTRA_CA_CERTS             node
#
# 风险点：no_proxy 命中 → 流量直连 → 对端证书由公共 CA 签发。若排他变量
#         指向的文件不含公共根，直连 TLS 校验断裂（curl error 60/77、
#         requests SSLError 等）——squid 本身无恙，是注入形态问题。
#         （2026-10-16 本机实测钉死语义：curl 8.22 对 SSL_CERT_FILE 走
#         排他加载（空文件 error 77 / 无关证书 error 60，dir 不兜底）；
#         s_client/OpenSSL 3.6 走 file∪dir union；node 只追加。）
#
# 本测试做三件事：
#   1. CA 文件形态取证：纯 squid CA（1 张证书）还是 bundle（squid CA+公共根）
#      —— bundle 是"直连与 MITM 双兼容"的唯一自洽形态
#   2. no_proxy 生效性：api.github.com 是否真的绕开 squid（无 CONNECT 行）
#   3. 工具 × 路径矩阵：直连（公共证书）/ 经 squid（MITM 重签）
#
# 用法：
#   bash test-squid/no-proxy-ca-test.sh                  # runner 上跑（pod env 已注入）
#   CA=/etc/ssl/certs/ca-certificates.crt bash ...       # 本地冒烟（指定任意 bundle）
#   SQUID_PROXY=http://1.2.3.4:3128 bash ...             # 本地显式指定 squid
#
# 判定：任一 TLS-FAIL → 退出 1（直连断裂=注入形态缺陷 / MITM 断裂=信任问题）；
#       OTHER-ERR（网络/协议层）记录不判红；SKIP（工具缺失/无代理 env）不影响。
#
# 输出：终端表 + ${RESULTS_DIR:-/tmp/test-squid-results}/no-proxy-ca.tsv
# =============================================================================
set -uo pipefail

RESULTS_DIR="${RESULTS_DIR:-/tmp/test-squid-results}"
TSV="$RESULTS_DIR/no-proxy-ca.tsv"
mkdir -p "$RESULTS_DIR"
printf 'probe\tpath\trc\tclass\n' > "$TSV"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

# ---------------------------------------------------------------------------
# 0. CA 文件与代理目标
# ---------------------------------------------------------------------------
CA="${CA:-/etc/squid-ca/squid-ca.pem}"
if [ ! -r "$CA" ]; then
    log "❌ CA 文件不可读: $CA（用 CA=<path> 覆盖；本地冒烟可传 /etc/ssl/certs/ca-certificates.crt）"
    exit 1
fi

# 经 squid 的腿：优先显式指定，其次 pod 注入的 HTTPS_PROXY
PX="${SQUID_PROXY:-${https_proxy:-${HTTPS_PROXY:-}}}"
# no_proxy 生效性检测需要知道是否有代理 env（set -u 安全取值）
HAS_PX="${https_proxy:-}${HTTPS_PROXY:-}"

log "CA 文件: $CA"
log "squid 代理: ${PX:-<无>（proxy 腿将 SKIP）}"

# ---------------------------------------------------------------------------
# 1. CA 形态取证：数证书张数
# ---------------------------------------------------------------------------
n_certs=$(grep -c 'BEGIN CERTIFICATE' "$CA" 2>/dev/null)
n_certs=${n_certs:-0}
if [ "$n_certs" -ge 2 ]; then
    log "### CA 形态: bundle（$n_certs 张证书 = squid CA + 公共根）→ 直连/MITM 双兼容预期 ✅"
elif [ "$n_certs" -eq 1 ]; then
    log "### CA 形态: 纯 squid CA（1 张证书）→ 排他语义工具的直连腿预期断裂 ⚠️"
else
    log "### CA 形态: 异常（0 张证书）→ 所有 TLS 腿预期断裂 ❌"
fi

# ---------------------------------------------------------------------------
# 1.5 BUNDLE_FIX 实验（BUNDLE_FIX=1 启用）：不等平台侧改 Secret，就地验证
#     "CA 变量指向含 squid CA 的系统 bundle"的修复可行性——即 postStart
#     临时修复形态。判定系统 bundle 是否已含 squid CA（SHA256 指纹比对）：
#     已含 → 全部 CA 变量直接重指向系统 bundle（零合成）；
#     不含 → 拼接兜底（squid CA + 系统 bundle → composite 文件再指向）。
#     注意：不是 ln——symlink 无法合并两个文件的内容，必须拼接。
# ---------------------------------------------------------------------------
if [ "${BUNDLE_FIX:-0}" = "1" ]; then
    SYS_BUNDLE=""
    for c in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
        [ -r "$c" ] && SYS_BUNDLE="$c" && break
    done
    if [ -n "$SYS_BUNDLE" ]; then
        match=$(python3 - "$CA" "$SYS_BUNDLE" <<'PYEOF' 2>/dev/null
import sys, hashlib
def certs(path):
    pems, cur = [], None
    for line in open(path, encoding='utf-8', errors='replace'):
        if 'BEGIN CERTIFICATE' in line:
            cur = []
        elif 'END CERTIFICATE' in line and cur is not None:
            pems.append(''.join(cur)); cur = None
        elif cur is not None:
            cur.append(line.strip())
    return {hashlib.sha256(p.encode()).hexdigest() for p in pems}
squid = certs(sys.argv[1])
bundle = certs(sys.argv[2])
print('MATCH' if squid and squid <= bundle else 'MISS')
PYEOF
)
        if [ "$match" = "MATCH" ]; then
            log "### BUNDLE_FIX: 系统 bundle（$SYS_BUNDLE）已含 squid CA → 6 个 CA 变量直接重指向它（零合成）"
            CA="$SYS_BUNDLE"
        else
            COMPOSITE="$RESULTS_DIR/composite-ca-bundle.pem"
            cat "$CA" "$SYS_BUNDLE" > "$COMPOSITE"
            n_comp=$(grep -c 'BEGIN CERTIFICATE' "$COMPOSITE" 2>/dev/null); n_comp=${n_comp:-0}
            log "### BUNDLE_FIX: 系统 bundle 不含 squid CA → 拼接合成（squid CA($n_certs) + $SYS_BUNDLE → $COMPOSITE，$n_comp 张）"
            CA="$COMPOSITE"
        fi
        n_ca=$(grep -c 'BEGIN CERTIFICATE' "$CA" 2>/dev/null); n_ca=${n_ca:-0}
        log "### BUNDLE_FIX: 最终 CA = $CA（$n_ca 张）→ 直连/MITM 双兼容预期 ✅"
    else
        log "### BUNDLE_FIX: 未找到系统 CA bundle（试过 ca-certificates.crt/ca-bundle.crt/cert.pem），跳过合成"
    fi
fi

# ---------------------------------------------------------------------------
# 2. 环境模拟：幂等 export 平台注入的全套变量（pod 已注入时无副作用）
#    本地冒烟时即"手动 set env"的等价物
# ---------------------------------------------------------------------------
export SSL_CERT_FILE="$CA"
export CURL_CA_BUNDLE="$CA"
export REQUESTS_CA_BUNDLE="$CA"
export GIT_SSL_CAINFO="$CA"
export PIP_CERT="$CA"
export NODE_EXTRA_CA_CERTS="$CA"

# ---------------------------------------------------------------------------
# 2.5 工具 bootstrap：极简 runner 镜像缺 python 工具链/node 时临时补装
#     （job 级安装不污染镜像；失败静默 → 对应格 SKIP，不影响其余矩阵）
#     背景（2026-10-16）：runner 层此前全绿是"SKIP 躲过 requests 直连腿"的
#     假绿——容器层已实证 requests-direct TLS-FAIL（排他 CA + 纯 squid CA）。
#     runner 层装齐后同格预期同红，矩阵不再依赖容器层代答。
# ---------------------------------------------------------------------------
SUDO=""
if [ "$(id -u)" != "0" ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
apt_install() { # apt_install <pkg>（install 失败时 update 后重试一次）
    $SUDO apt-get install -y -q "$1" >/dev/null 2>&1 && return 0
    $SUDO apt-get update -q >/dev/null 2>&1
    $SUDO apt-get install -y -q "$1" >/dev/null 2>&1
}
if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import requests' 2>/dev/null; then
    log "bootstrap: python3 缺 requests → 尝试补装"
    if apt_install python3-requests || python3 -m pip install --user -q requests >/dev/null 2>&1; then
        python3 -c 'import requests' 2>/dev/null && log "bootstrap: requests 就绪"
    fi
fi
if command -v python3 >/dev/null 2>&1 && ! python3 -m pip --version >/dev/null 2>&1 \
   && ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
    apt_install python3-pip && log "bootstrap: pip 就绪"
fi
if ! command -v node >/dev/null 2>&1; then
    apt_install nodejs && command -v node >/dev/null 2>&1 && log "bootstrap: nodejs 就绪"
fi

# ---------------------------------------------------------------------------
# 3. probe 封装：执行命令并按 stderr/stdout 分类
#    OK / TLS-FAIL（证书信任断裂）/ OTHER-ERR（网络/协议等）/ SKIP
# ---------------------------------------------------------------------------
probe() { # probe <label> <path:direct|proxy|npx> <cmd...>
    local label="$1" path="$2"; shift 2
    local out rc cls
    out=$("$@" 2>&1); rc=$?
    if [ $rc -eq 0 ]; then
        cls=OK
    elif grep -qiE 'certificate verify failed|unable to get local issuer|self.signed certificate|CERTIFICATE_VERIFY_FAILED|SSL certificate problem|error adding trust anchors|alert certificate|ssl routines|unable to verify the first certificate|X509|no certificate or crl found' <<<"$out"; then
        cls=TLS-FAIL
    else
        cls=OTHER-ERR
    fi
    printf '%s\t%s\t%s\t%s\n' "$label" "$path" "$rc" "$cls" >> "$TSV"
    local tail1
    tail1=$(head -n 2 <<<"$out" | tr '\n' ' ' | cut -c1-110)
    if [ "$cls" = OK ]; then
        log "### [$label/$path] OK  $tail1"
    else
        log "### [$label/$path] $cls (rc=$rc)  $tail1"
    fi
}

skip() { # skip <label> <path> <原因>
    printf '%s\t%s\t-\tSKIP\n' "$1" "$2" >> "$TSV"
    log "### [$1/$2] SKIP — $3"
}

DIRECT_URL="${DIRECT_URL:-https://api.github.com}"   # no_proxy 已覆盖，公共 CA 签发
PROXY_URL="${PROXY_URL:-https://github.com}"         # 不在 no_proxy，CONNECT 经 squid MITM

log "―――――――――― no_proxy 生效性 ――――――――――"
if [ -n "$HAS_PX" ]; then
    # curl 尊重 no_proxy：命中 → verbose 无 CONNECT 行（直连 TCP）；未命中 → CONNECT <squid>
    if curl -sv --max-time 20 "$DIRECT_URL" -o /dev/null 2>&1 | grep -q 'CONNECT '; then
        printf 'npx-hit\tnpx\t3\tNO_PROXY-MISS\n' >> "$TSV"
        log "### [npx-hit] ❌ api.github.com 未命中 no_proxy，流量仍走 squid CONNECT（no_proxy 配置失效或域名写法不匹配）"
    else
        printf 'npx-hit\tnpx\t0\tOK\n' >> "$TSV"
        log "### [npx-hit] OK  api.github.com 绕开 squid 直连（no_proxy 生效）"
    fi
else
    skip npx-hit npx "本环境无 https_proxy 注入"
fi

log "―――――――――― 直连腿（公共 CA 证书；no_proxy 语义） ――――――――――"
probe curl-direct direct curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 20 "$DIRECT_URL"

if command -v openssl >/dev/null 2>&1; then
    # SSL_CERT_FILE 库级 union 语义对照组
    probe sclient-direct direct sh -c "echo | openssl s_client -connect api.github.com:443 -brief 2>&1 | grep -q 'Verification: OK'"
fi

if command -v python3 >/dev/null 2>&1 && python3 -c 'import requests' 2>/dev/null; then
    # REQUESTS_CA_BUNDLE 排他语义（python 系直连断裂的高发位）
    probe requests-direct direct python3 -c "import requests; print(requests.get('$DIRECT_URL', timeout=20).status_code)"
else
    skip requests-direct direct "python3/requests 不可用"
fi

if command -v node >/dev/null 2>&1; then
    # NODE_EXTRA_CA_CERTS 追加语义（内置 Mozilla 根仍在，直连预期 OK）
    probe node-direct direct node -e "require('https').get('$DIRECT_URL',r=>{console.log('HTTP',r.statusCode);process.exit(0)}).on('error',e=>{console.error(e.message);process.exit(1)})"
else
    skip node-direct direct "node 不可用"
fi

log "―――――――――― 经 squid 腿（MITM 重签证书；squid CA 语义） ――――――――――"
if [ -n "$PX" ]; then
    probe curl-proxy proxy curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -x "$PX" "$PROXY_URL"

    if command -v git >/dev/null 2>&1; then
        # GIT_SSL_CAINFO 排他语义 + CONNECT 隧道（git 生产形态）
        probe git-proxy proxy git ls-remote "https://github.com/octocat/Hello-World.git" HEAD
    fi

    if command -v python3 >/dev/null 2>&1 && python3 -c 'import requests' 2>/dev/null; then
        probe requests-proxy proxy python3 -c "import requests; print(requests.get('$PROXY_URL', timeout=30, proxies={'https':'$PX'}).status_code)"
    else
        skip requests-proxy proxy "python3/requests 不可用"
    fi

    PIP_BIN=""
    command -v pip3 >/dev/null 2>&1 && PIP_BIN="$(command -v pip3)"
    [ -z "$PIP_BIN" ] && command -v pip >/dev/null 2>&1 && PIP_BIN="$(command -v pip)"
    [ -z "$PIP_BIN" ] && python3 -m pip --version >/dev/null 2>&1 && PIP_BIN="python3 -m pip"
    if [ -n "$PIP_BIN" ]; then
        # PIP_CERT + MITM（走代理拉一个小包）
        probe pip-proxy proxy $PIP_BIN download --no-deps -q -d /tmp/np-ca-test --proxy "$PX" six
    else
        skip pip-proxy proxy "pip 不可用"
    fi
else
    log "（无 squid 代理可用，proxy 腿全部 SKIP——本地冒烟场景）"
    skip curl-proxy  proxy "无代理 env"
    skip git-proxy   proxy "无代理 env"
    skip requests-proxy proxy "无代理 env"
    skip pip-proxy   proxy "无代理 env"
fi

# ---------------------------------------------------------------------------
# 4. 汇总判定
# ---------------------------------------------------------------------------
log "―――――――――― 结果汇总（$TSV） ――――――――――"
column -t -s $'\t' "$TSV" 2>/dev/null || cat "$TSV"

tls_fail=$(awk -F'\t' 'NR>1 && $4=="TLS-FAIL"' "$TSV" | wc -l)
other_err=$(awk -F'\t' 'NR>1 && $4=="OTHER-ERR"' "$TSV" | wc -l)

if [ "$tls_fail" -gt 0 ]; then
    log "❌ 存在 $tls_fail 个 TLS-FAIL："
    awk -F'\t' 'NR>1 && $4=="TLS-FAIL" {print "    - " $1 " / " $2}' "$TSV"
    log "   直连腿红 = 排他 CA 变量挤掉公共根（squid-ca.pem 需为 squid CA+公共根 bundle）"
    log "   代理腿红 = MITM 信任断裂（CA 文件缺 squid CA 或未注入到工具）"
    exit 1
fi
[ "$other_err" -gt 0 ] && log "⚠️ $other_err 个 OTHER-ERR（网络/协议层，记录不判红）"
log "✅ 全部 TLS 校验通过（直连与 MITM 双路径自洽；CA 形态见开头取证行）"
exit 0
