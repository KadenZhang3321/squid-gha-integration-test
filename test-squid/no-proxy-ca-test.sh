#!/usr/bin/env bash
# =============================================================================
# no-proxy-ca-test.sh —— no_proxy 直连 × CA 注入变量组 矩阵测试
#
# 背景：平台向 runner / 工作负载 pod 注入一组 CA 环境变量。按工具实现分三类语义：
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
# 注入形态两代（PR opensourceways/ascend-ci-deployment#2017 分界，2026-10-19）：
#   旧（legacy）：5 个替换型全部指向 /etc/squid-ca/squid-ca.pem（纯 squid CA，
#                 1 张）——排他语义工具的 no_proxy 直连腿必断（缺陷指纹）
#   新（bundle）：5 个替换型指向 /etc/ca-bundle/squid-bundle.pem（postStart 由
#                 inject-squid-ca.sh 合成：系统 bundle + squid CA，emptyDir 落盘）
#                 ——直连/MITM 双兼容；NODE_EXTRA_CA_CERTS 追加语义两代都指单证书
#   接线状态仅 gy-006（PR #2017），生产 runner 仍为 legacy → 本测试按实际 env
#   自动识别形态并给出对应判定口径（见 1.2 节）。
#
# 风险点：no_proxy 命中 → 流量直连 → 对端证书由公共 CA 签发。若排他变量
#         指向的文件不含公共根，直连 TLS 校验断裂（curl error 60/77、
#         requests SSLError 等）——squid 本身无恙，是注入形态问题。
#         （2026-10-16 本机实测钉死语义：curl 8.22 对 SSL_CERT_FILE 走
#         排他加载（空文件 error 77 / 无关证书 error 60，dir 不兜底）；
#         s_client/OpenSSL 3.6 走 file∪dir union；node 只追加。）
#         新形态新增风险：bundle 文件由 postStart 生成——未挂 emptyDir /
#         postStart 未跑 / 合成自检失败时文件缺失或坏 PEM → 所有 TLS 腿断。
#
# 本测试做五件事：
#   1. CA 文件形态取证：纯 squid CA（1 张）还是 bundle（squid CA+公共根）
#   2. 注入接线判定：pod env 实际指向 legacy 还是 bundle 形态（PR #2017）
#   3. no_proxy 生效性：api.github.com 是否真的绕开 squid（无 CONNECT 行）
#   4. 工具 × 路径矩阵：直连（公共证书）/ 经 squid（MITM 重签）；两种形态下
#      TLS-FAIL 都判红——legacy 红 = 暴露已知缺陷，bundle 红 = 接线/合成真故障
#   5. 新增直连域生效性（PR ascend-ci-deployment#2194 首批）：云元数据端点
#      （100.100.100.200 / 169.254.169.254 / metadata.google.internal）与不可缓存
#      的 LLM 统计/API 域（stats.vllm.ai / api.siliconflow.cn / api.deepseek.com）
#      是否真的绕开 squid——按 runner set 是否已纳入本批自适应判定（见 3.6 节）
#
# 用法：
#   bash test-squid/no-proxy-ca-test.sh                  # runner 上跑（pod env 已注入）
#   CA=/etc/ssl/certs/ca-certificates.crt bash ...       # 本地冒烟（指定任意 bundle）
#   SQUID_PROXY=http://1.2.3.4:3128 bash ...             # 本地显式指定 squid
#   NP_DOMAIN_STRICT=1 bash ...                          # 新增直连域必须全部命中
#                                                        # NO_PROXY（分批推进期默认 0）
#   NP_DOMAIN_ENDPOINTS=... bash ...                     # 覆盖新增直连域清单
#                                                        # （逗号分隔的完整 URL）
#
# 判定：任一 TLS-FAIL → 退出 1（直连断裂=注入形态缺陷 / MITM 断裂=信任问题）；
#       NO_PROXY 已声明的新增直连域仍走代理 → 退出 1（不可缓存域被 squid 接走）；
#       OTHER-ERR（网络/协议层）记录不判红；SKIP（工具缺失/无代理 env/分批未覆盖）不影响。
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
#    CA 目标解析优先级：显式 CA= > pod 注入的替换型 env（PR #2017 新形态下
#    即 /etc/ca-bundle/squid-bundle.pem）> 传统默认（纯 squid CA）
# ---------------------------------------------------------------------------
CA="${CA:-${REQUESTS_CA_BUNDLE:-${SSL_CERT_FILE:-/etc/squid-ca/squid-ca.pem}}}"
if [ ! -r "$CA" ]; then
    case "$CA" in
        *squid-bundle.pem)
            log "❌ CA 文件不可读: $CA —— PR #2017 新形态：env 已指向 /etc/ca-bundle/squid-bundle.pem 但文件不存在"
            log "   → 检查该 runner set 是否挂了 ca-bundle emptyDir、postStart 是否调用 inject-squid-ca.sh、合成是否失败" ;;
        *)
            log "❌ CA 文件不可读: $CA（用 CA=<path> 覆盖；本地冒烟可传 /etc/ssl/certs/ca-certificates.crt）" ;;
    esac
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
# 1.2 注入接线判定（PR #2017）：pod env 的替换型变量实际指向哪一代形态
#     bundle接线 = env 指向 squid-bundle.pem 且文件为多张 bundle → 全矩阵
#                  预期绿，TLS-FAIL 即真故障（接线/合成问题）
#     legacy    = env 指向纯 squid-ca.pem → requests-direct 预期红（已知
#                 缺陷指纹；红不是套件误报，是暴露平台未接线）
#     broken接线 = env 指向 squid-bundle.pem 但文件缺失/单张 → 0 节已报错退出
# ---------------------------------------------------------------------------
INJ_FORM="legacy"
case "$(basename "$CA")" in
    squid-bundle.pem)
        if [ "$n_certs" -ge 2 ]; then
            INJ_FORM="bundle"
            log "### 接线判定: bundle 形态（PR #2017 已接线）→ 全矩阵预期绿 ✅"
        fi ;;
    squid-ca.pem)
        [ "$n_certs" -eq 1 ] && log "### 接线判定: legacy 形态（PR #2017 未接线到本 runner set）→ requests-direct 预期红 ⚠️" ;;
esac
export NP_CA_INJ_FORM="$INJ_FORM"

# ---------------------------------------------------------------------------
# 1.5 BUNDLE_FIX 实验（BUNDLE_FIX=1 启用）：仅对 legacy 形态环境有意义——
#     不等平台侧接线，就地验证"CA 变量指向含 squid CA 的系统 bundle"的修复
#     可行性。判定系统 bundle 是否已含 squid CA（SHA256 指纹比对）：
#     已含 → 全部 CA 变量直接重指向系统 bundle（零合成）；
#     不含 → 拼接兜底（squid CA + 系统 bundle → composite 文件再指向）。
#     bundle 形态（PR #2017 已接线）下自动跳过。
# ---------------------------------------------------------------------------
if [ "${BUNDLE_FIX:-0}" = "1" ]; then
    if [ "$INJ_FORM" = "bundle" ]; then
        log "### BUNDLE_FIX: 已是 bundle 形态（PR #2017 接线生效），跳过实验"
    else
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
            n_sys=$(grep -c 'BEGIN CERTIFICATE' "$SYS_BUNDLE" 2>/dev/null); n_sys=${n_sys:-0}
            COMPOSITE="$RESULTS_DIR/composite-ca-bundle.pem"
            # ⚠️ ConfigMap 挂载的 squid-ca.pem 末尾常无换行符——直接 cat 拼接会把
            # END CERTIFICATE 与下一张 MII... 粘成一行 → 坏 PEM → curl error 77
            # （run 38880372240 实证，3 条腿连带全红）。拼接前保障尾换行：
            # tail -c 1 经命令替换后非空 = 最后字节不是换行 → 补一个换行。
            { cat "$CA"; [ -n "$(tail -c 1 "$CA")" ] && echo; cat "$SYS_BUNDLE"; } > "$COMPOSITE"
            n_comp=$(grep -c 'BEGIN CERTIFICATE' "$COMPOSITE" 2>/dev/null); n_comp=${n_comp:-0}
            # 拼接自检：① BEGIN 张数 = 两输入之和；② 行边界干净（BEGIN/END 必须独占行，
            # 计数抓不住粘连——本次 bug 即计数通过但 END 粘注释导致解析崩）
            if [ "$n_comp" -ne $((n_certs + n_sys)) ] \
               || grep -q -- '-----BEGIN CERTIFICATE-----[^[:space:]]' "$COMPOSITE" \
               || grep -q -- '-----END CERTIFICATE-----[^[:space:]]' "$COMPOSITE"; then
                log "### BUNDLE_FIX: 拼接自检失败（BEGIN=$n_comp/$((n_certs + n_sys)) 或存在粘连行）→ composite 坏 PEM，跳过 fix 保持原 CA"
            else
                log "### BUNDLE_FIX: 系统 bundle 不含 squid CA → 拼接合成（squid CA($n_certs) + $SYS_BUNDLE → $COMPOSITE，$n_comp 张）"
                CA="$COMPOSITE"
            fi
        fi
        n_ca=$(grep -c 'BEGIN CERTIFICATE' "$CA" 2>/dev/null); n_ca=${n_ca:-0}
        log "### BUNDLE_FIX: 最终 CA = $CA（$n_ca 张）→ 直连/MITM 双兼容预期 ✅"
        else
            log "### BUNDLE_FIX: 未找到系统 CA bundle（试过 ca-certificates.crt/ca-bundle.crt/cert.pem），跳过合成"
        fi
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
# 3.5 kubectl（Go 客户端）× 172.16.0.0/12 no_proxy 语义
#     平台 NO_PROXY 含 172.16.0.0/12（集群内网段）。Go 的
#     http.ProxyFromEnvironment 与 curl 各自实现 no_proxy 解析，CIDR 命中行为
#     必须用 Go 客户端独立验证：mock kubeconfig 指向 172.16.0.0/12 内的伪 API
#     server，用本地"记账代理"（收到 CONNECT 即落盘并回 502）代替 squid 观测：
#       no_proxy 命中 → 客户端直连 → 记账代理零 CONNECT（squid 看不到该请求）
#       未命中       → CONNECT 到达记账代理（真实环境即被 squid 接走）
#     期望值按实际注入的 NO_PROXY 计算（各集群配置不同不误判）；公网地址
#     203.0.113.1（TEST-NET-3）作正样本，证明观测方法本身有效。
# ---------------------------------------------------------------------------
KUBECTL=""
command -v kubectl >/dev/null 2>&1 && KUBECTL="$(command -v kubectl)"
if [ -z "$KUBECTL" ]; then
    # 镜像源下载（二进制落 /tmp，不进 artifacts）。背景：gy-006 上 dl.k8s.io 拉不动
    # （fastly 出口不通，cabundle artifact 里没有 kubectl、两行全 SKIP）。
    # 策略：先走国内镜像的 deb 包——pkgs.k8s.io 的结构被 USTC/NJU 完整镜像，
    # kubectl_<ver>_<arch>.deb 仅 11MB（裸二进制 61MB），解包即得 /usr/bin/kubectl；
    # 失败再退回裸二进制源（官方 dl.k8s.io / DaoCloud 反代）。
    # 可用 KUBECTL_DEB_MIRRORS / KUBECTL_BIN_MIRRORS 覆盖（空格分隔 base）。
    case "$(uname -m)" in
        aarch64|arm64) KARCH=arm64 ;;
        *)             KARCH=amd64 ;;
    esac
    KNP_BIN_DIR="$(mktemp -d /tmp/kubectl-np.XXXXXX)"

    # (a) deb 包源
    for base in ${KUBECTL_DEB_MIRRORS:-https://mirrors.ustc.edu.cn/kubernetes/core%3A/stable%3A/v1.33/deb https://mirrors.nju.edu.cn/kubernetes/core%3A/stable%3A/v1.33/deb https://pkgs.k8s.io/core:/stable:/v1.33/deb}; do
        base="${base%/}"
        pkg=$(curl -fsSL --max-time 60 "$base/Packages" 2>/dev/null | awk -v a="$KARCH" '
            /^Package: /{p=$2} /^Architecture: /{ar=$2}
            /^Filename: /{if (p=="kubectl" && ar==a) {print $2; exit}}')
        if [ -z "$pkg" ]; then
            log "bootstrap: $base 无 kubectl/$KARCH 条目，试下一源"
            continue
        fi
        if curl -fsSL --max-time 300 -o "$KNP_BIN_DIR/kubectl.deb" "$base/$pkg" 2>/dev/null \
           && { dpkg-deb -x "$KNP_BIN_DIR/kubectl.deb" "$KNP_BIN_DIR/x" 2>/dev/null \
                || { mkdir -p "$KNP_BIN_DIR/x" \
                     && (cd "$KNP_BIN_DIR/x" && ar x ../kubectl.deb && tar -xf data.tar.*); }; } \
           && [ -x "$KNP_BIN_DIR/x/usr/bin/kubectl" ] \
           && "$KNP_BIN_DIR/x/usr/bin/kubectl" version --client >/dev/null 2>&1; then
            KUBECTL="$KNP_BIN_DIR/x/usr/bin/kubectl"
            log "bootstrap: kubectl（deb $pkg）← $base"
            break
        fi
        rm -rf "$KNP_BIN_DIR/x" "$KNP_BIN_DIR/kubectl.deb"
        log "bootstrap: $base 不可用，试下一源"
    done

    # (b) 裸二进制源（deb 全败时兜底）
    if [ -z "$KUBECTL" ]; then
        for base in ${KUBECTL_BIN_MIRRORS:-https://dl.k8s.io https://files.m.daocloud.io/dl.k8s.io}; do
            base="${base%/}"
            ver="${KUBECTL_VERSION:-}"
            [ -z "$ver" ] && ver=$(curl -sSL --max-time 20 "$base/release/stable.txt" 2>/dev/null | tr -d '\r\n')
            [ -z "$ver" ] && ver="v1.33.0"   # stable.txt 取不到时钉版本兜底
            if curl -fsSL --max-time 300 -o "$KNP_BIN_DIR/kubectl" \
                   "$base/release/$ver/bin/linux/$KARCH/kubectl" 2>/dev/null \
               && chmod +x "$KNP_BIN_DIR/kubectl" \
               && "$KNP_BIN_DIR/kubectl" version --client >/dev/null 2>&1; then
                KUBECTL="$KNP_BIN_DIR/kubectl"
                log "bootstrap: kubectl $ver（$KARCH）← $base"
                break
            fi
            rm -f "$KNP_BIN_DIR/kubectl"
            log "bootstrap: $base 不可用，试下一源"
        done
    fi
fi

if [ -z "$KUBECTL" ]; then
    skip kubectl-ctl proxy "kubectl 不可用且 bootstrap 失败"
    skip kubectl-17216 npx "kubectl 不可用且 bootstrap 失败"
elif ! command -v python3 >/dev/null 2>&1; then
    skip kubectl-ctl proxy "python3 不可用（记账代理无法启动）"
    skip kubectl-17216 npx "python3 不可用（记账代理无法启动）"
else
    log "―――――――――― kubectl（Go 客户端）× 172.16.0.0/12 no_proxy ――――――――――"
    NP_ENV="${NO_PROXY:-${no_proxy:-}}"
    KNP_DIR="$RESULTS_DIR/kubectl-npx"; mkdir -p "$KNP_DIR"
    proxy_log="$KNP_DIR/proxy.log"; : > "$proxy_log"
    proxy_port=$((19000 + RANDOM % 500))
    python3 - "$proxy_port" "$proxy_log" <<'PYEOF' >/dev/null 2>&1 &
import socket, sys, threading
port, logf = int(sys.argv[1]), sys.argv[2]
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', port)); srv.listen(16); srv.settimeout(60)
def handle(c):
    try:
        c.settimeout(5)
        first = c.recv(4096).decode('latin-1', 'replace').split('\r\n')[0]
        if first:
            with open(logf, 'a') as f: f.write(first + '\n')
        c.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
    except OSError:
        pass
    finally:
        c.close()
while True:
    try:
        c, _ = srv.accept()
    except socket.timeout:
        break
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PYEOF
    proxy_pid=$!
    sleep 1

    mk_kubeconfig() { # mk_kubeconfig <文件> <server>
        cat > "$1" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: np
  cluster:
    server: $2
    insecure-skip-tls-verify: true
contexts:
- name: np
  context: {cluster: np, user: np}
current-context: np
users:
- name: np
  user:
    token: mock   # 空 user 会触发 kubectl 交互式 "Please enter Username"
EOF
    }

    fake_px="http://127.0.0.1:$proxy_port"
    np_kubectl() { # np_kubectl <label> <server> → yes/no：记账代理是否收到 CONNECT
        local label="$1" server="$2" before after
        mk_kubeconfig "$KNP_DIR/$label.yaml" "$server"
        before=$(wc -l < "$proxy_log")
        timeout 25 env HTTP_PROXY="$fake_px" HTTPS_PROXY="$fake_px" \
            NO_PROXY="$NP_ENV" no_proxy="$NP_ENV" \
            "$KUBECTL" --kubeconfig "$KNP_DIR/$label.yaml" --request-timeout=8s \
            get --raw /healthz > "$KNP_DIR/$label.out" 2>&1
        sleep 1
        after=$(wc -l < "$proxy_log")
        [ "$after" -gt "$before" ] && echo yes || echo no
    }

    in_ctl=$(np_kubectl ctl-public https://203.0.113.1:6443)
    in_tgt=$(np_kubectl tgt-17216 https://172.16.255.254:6443)
    kill "$proxy_pid" 2>/dev/null; wait "$proxy_pid" 2>/dev/null

    if [ "$in_ctl" = yes ]; then
        printf 'kubectl-ctl\tproxy\t0\tOK\n' >> "$TSV"
        log "### [kubectl-ctl/proxy] OK  不在 no_proxy 的公网地址确实发出 CONNECT（观测方法有效）"
    else
        printf 'kubectl-ctl\tproxy\t-\tSKIP\n' >> "$TSV"
        log "### [kubectl-ctl/proxy] SKIP 记账代理未收到 CONNECT（kubectl 未读 proxy env？）——无法判定，记录不判红"
    fi

    KUBECTL_NPX_FAIL=0
    case ",$NP_ENV," in
        *,172.16.0.0/12,*)
            if [ "$in_tgt" = no ]; then
                printf 'kubectl-17216\tnpx\t0\tOK\n' >> "$TSV"
                log "### [kubectl-17216/npx] OK  172.16.255.254 命中 no_proxy → 直连，记账代理零 CONNECT（squid 不会看到该请求）"
            else
                printf 'kubectl-17216\tnpx\t3\tNO_PROXY-MISS\n' >> "$TSV"
                log "### [kubectl-17216/npx] ❌ NO_PROXY 已含 172.16.0.0/12，但 kubectl 仍发出 CONNECT → 该请求会被 squid 接走（Go 客户端 CIDR 语义未生效）"
                KUBECTL_NPX_FAIL=1
            fi ;;
        *)
            if [ "$in_tgt" = yes ]; then
                printf 'kubectl-17216\tproxy\t0\tOK\n' >> "$TSV"
                log "### [kubectl-17216/proxy] OK  NO_PROXY 未含 172.16.0.0/12 → CONNECT 到达代理（流量按配置走 squid）"
            else
                printf 'kubectl-17216\tproxy\t-\tSKIP\n' >> "$TSV"
                log "### [kubectl-17216/proxy] SKIP NO_PROXY 未配置该网段但也没发 CONNECT——观测异常，记录不判红"
            fi ;;
    esac
fi

# ---------------------------------------------------------------------------
# 3.6 新增直连域生效性（PR opensourceways/ascend-ci-deployment#2194 首批）
#     云元数据端点（100.100.100.200 / 169.254.169.254 / metadata.google.internal）
#     与不可缓存的 LLM 统计/API 域（stats.vllm.ai / api.siliconflow.cn /
#     api.deepseek.com）已写入 gy-006 linux-amd64-cpu-2 的 pod 模板 NO_PROXY。
#     本组只验一个契约：这些域是否真的绕开 squid（curl 不再读代理变量）。
#
#     判定按"该 runner set 是否已纳入本批"自适应（PR 分批推进，未覆盖 ≠ 故障）：
#       NO_PROXY 已含该域 + 仍走代理 → NO_PROXY-MISS，判红（写法/覆盖缺陷）
#       NO_PROXY 已含该域 + 直连     → OK
#       NO_PROXY 未含该域            → SKIP（NP_DOMAIN_STRICT=1 时改为判红）
#
#     观测方法：curl -v 决定走代理时打印 "Uses proxy env variable HTTPS_PROXY"，
#     NO_PROXY 命中则不出该行。不需要真实出网（DNS 失败/超时都不影响判定），
#     因此对 link-local 元数据地址与境外 API 域同样可用。
# ---------------------------------------------------------------------------
NP_DOMAIN_ENDPOINTS="${NP_DOMAIN_ENDPOINTS:-http://100.100.100.200,http://169.254.169.254,http://metadata.google.internal,https://stats.vllm.ai,https://api.siliconflow.cn,https://api.deepseek.com}"
NP_DOMAIN_STRICT="${NP_DOMAIN_STRICT:-0}"
NP_DOMAIN_FAIL=0

# use_px <curl verbose 输出> → 0 表示 curl 决定走代理
use_px() { grep -qE 'Uses proxy env variable (HTTPS?_PROXY|ALL_PROXY|https?_proxy|all_proxy)' <<<"$1"; }

# np_has_domain <host> → 0 表示该主机被 NO_PROXY 覆盖（大小写两份取并集，
# 与 curl 的实际读取行为一致）
np_has_domain() {
    local host list
    host=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    for list in "${NO_PROXY:-}" "${no_proxy:-}"; do
        list=$(printf '%s' "$list" | tr -d '[:space:]' | tr 'A-Z' 'a-z')
        case ",$list," in
            *,\*,*|*,"$host",*|*,".$host",*) return 0 ;;
        esac
    done
    return 1
}

if [ -z "$HAS_PX" ]; then
    skip np-domain-all npx "本环境无 http(s)_proxy 注入，无法判定是否绕开代理"
elif ! command -v curl >/dev/null 2>&1; then
    skip np-domain-all npx "curl 不可用"
else
    log "―――――――――― 新增直连域生效性（PR #2194 首批） ――――――――――"
    # 对照组：不在 NO_PROXY 的 github.com 必须走代理，否则本组观测不可信
    ctl_out=$(curl -sv --max-time 8 https://github.com -o /dev/null 2>&1)
    if use_px "$ctl_out"; then
        printf 'np-domain-ctl\tproxy\t0\tOK\n' >> "$TSV"
        log "### [np-domain-ctl/proxy] OK  对照域 github.com 仍走代理（观测方法有效）"
    else
        printf 'np-domain-ctl\tproxy\t-\tSKIP\n' >> "$TSV"
        log "### [np-domain-ctl/proxy] SKIP 对照域也未走代理（NO_PROXY 全通配或 curl 未读代理 env）——本组观测不可信，不判红"
    fi

    for ep in ${NP_DOMAIN_ENDPOINTS//,/ }; do
        host=${ep#*://}; host=${host%%/*}
        if np_has_domain "$host"; then
            out=$(curl -sv --max-time 8 "$ep" -o /dev/null 2>&1)
            if use_px "$out"; then
                printf 'np-domain-%s\tnpx\t3\tNO_PROXY-MISS\n' "$host" >> "$TSV"
                log "### [np-domain-$host/npx] ❌ NO_PROXY 已含该域但仍走代理 → 该流量会被 squid 接走（不可缓存域被缓存/计费）"
                NP_DOMAIN_FAIL=$((NP_DOMAIN_FAIL + 1))
            else
                printf 'np-domain-%s\tnpx\t0\tOK\n' "$host" >> "$TSV"
                log "### [np-domain-$host/npx] OK  命中 NO_PROXY → curl 直连（未读代理变量）"
            fi
        elif [ "$NP_DOMAIN_STRICT" = "1" ]; then
            printf 'np-domain-%s\tnpx\t3\tNO_PROXY-MISS\n' "$host" >> "$TSV"
            log "### [np-domain-$host/npx] ❌ NO_PROXY 未含该域（NP_DOMAIN_STRICT=1 要求本 runner set 纳入）"
            NP_DOMAIN_FAIL=$((NP_DOMAIN_FAIL + 1))
        else
            printf 'np-domain-%s\tnpx\t-\tSKIP\n' "$host" >> "$TSV"
            log "### [np-domain-$host/npx] SKIP  该 runner set 的 NO_PROXY 未含此域（PR #2194 分批推进，仅覆盖 gy-006 cm 模板）"
        fi
    done
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
    if [ "$INJ_FORM" = "bundle" ]; then
        log "   bundle 接线形态（PR #2017）下不应出现 TLS-FAIL → 检查 /etc/ca-bundle 合成产物"
        log "   （postStart 是否执行、emptyDir 是否挂载、合成自检是否通过、squid CA 是否轮换未重合成）"
    else
        log "   legacy 形态：直连腿红 = 已知缺陷指纹（排他 CA 变量挤掉公共根），接线 PR #2017 后转绿"
        log "   legacy 形态下代理腿红才是异常（MITM 信任断裂：CA 文件缺 squid CA 或未注入到工具）"
    fi
    exit 1
fi
[ "$other_err" -gt 0 ] && log "⚠️ $other_err 个 OTHER-ERR（网络/协议层，记录不判红）"
# kubectl 的 no_proxy 失效是明确缺陷（NO_PROXY 已声明该网段却仍进 squid），
# 与 npx-hit 的数据留档口径不同：这一条直接判红。
if [ "${KUBECTL_NPX_FAIL:-0}" -gt 0 ]; then
    log "❌ kubectl 对 172.16.0.0/12 的 no_proxy 未生效：内网 API 请求会被 squid 接走"
    log "   → 检查 NO_PROXY 大小写/写法（Go 需 CIDR 形式 172.16.0.0/12）、是否被 job env 覆盖"
    exit 1
fi
# 新增直连域：NO_PROXY 已声明却仍走代理 = 配置未生效（不可缓存流量被 squid 接走）。
if [ "${NP_DOMAIN_FAIL:-0}" -gt 0 ]; then
    log "❌ 新增直连域有 $NP_DOMAIN_FAIL 个未绕开代理："
    awk -F'\t' 'NR>1 && $1 ~ /^np-domain-/ && $1 != "np-domain-ctl" && $4=="NO_PROXY-MISS" {print "    - " $1}' "$TSV"
    log "   → 检查 NO_PROXY 实际 env（大小写两域名都要）、ConfigMap 是否已 rollout 到运行中的 pod"
    exit 1
fi
if [ "$INJ_FORM" = "bundle" ]; then
    log "✅ bundle 形态（PR #2017）：直连（公共根）与 MITM（squid CA）双路径全绿——同一信任源自洽"
else
    log "✅ 全部 TLS 校验通过（直连与 MITM 双路径自洽；CA 形态见开头取证行）"
fi
exit 0
