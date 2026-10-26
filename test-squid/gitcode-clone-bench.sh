#!/usr/bin/env bash
# =============================================================================
# gitcode-clone-bench.sh —— 只测 gitcode clone 的耗时与吞吐（R22）
#
# 前提：pod 模板的 postStart 已把 https://gitcode.com/ 重写到缓存后端
#       （/root/.gitconfig 里的 url.<backend>.insteadOf），否则本脚本判失败。
#
# 输入（env）：
#   GITCODE_REPO     目标仓库，默认 https://gitcode.com/cann/catlass.git
#   GITCODE_PROXY    期望的缓存后端基址（仅用于断言，空=不断言）
#   CLONE_MODE       full=--single-branch（不带 depth，可进后端 pack 缓存）
#                    shallow=--depth 1（多数后端默认不缓存，只测拉取速度）
#   ITERATIONS       克隆次数，默认 5；第 1 次为冷启动，其余为热路径
#   BASELINE         1=额外克隆一次上游 gitcode.com 作对照（GIT_CONFIG_GLOBAL=/dev/null 跳过 insteadOf）
#   REWRITE_STRICT   1=重写未生效即判失败（默认 1）
#   RESULTS_DIR      结果目录，默认 /tmp/gitcode-bench
#
# 输出：
#   clone.tsv        每次克隆：iter / mode / exit / ms / bytes / MBps / url
#   summary.md       汇总：冷/热耗时、加速比、中位数、吞吐
#
# 退出码：有克隆失败 → 1；重写断言失败 → 1；否则 0（性能数据不判红）
# =============================================================================
set -uo pipefail

REPO="${GITCODE_REPO:-https://gitcode.com/cann/catlass.git}"
BACKEND="${GITCODE_PROXY:-}"
MODE="${CLONE_MODE:-full}"
ITER="${ITERATIONS:-5}"
BASELINE="${BASELINE:-0}"
STRICT="${REWRITE_STRICT:-1}"
OUT="${RESULTS_DIR:-/tmp/gitcode-bench}"

mkdir -p "$OUT"
CSV="$OUT/clone.tsv"
SUMMARY="$OUT/summary.md"
printf 'iter\tmode\texit\tms\tbytes\tMBps\turl\n' > "$CSV"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
norm() { printf '%s' "${1%/}"; }

path="${REPO#*gitcode.com}"                 # /cann/catlass.git
origin=$(norm "${REPO%"$path"}")           # https://gitcode.com

# --- ① 断言 insteadOf 生效，并从展开结果反推后端基址 -------------------------
expanded=$(git ls-remote --get-url "$REPO" 2>/dev/null)
log "URL 展开: $REPO -> ${expanded:-<空>}"
base=""
case "$expanded" in
    *"$path") base=$(norm "${expanded%"$path"}") ;;
esac
if [ -z "$base" ] || [ "$base" = "$origin" ]; then
    log "❌ insteadOf 未生效（展开结果不是缓存后端）。该 runner 未注入重写？"
    [ "$STRICT" = 1 ] && exit 1
    base="$origin"
fi
if [ -n "$BACKEND" ] && [ "$base" != "$(norm "$BACKEND")" ]; then
    log "⚠️ 实际后端 $base 与期望 $(norm "$BACKEND") 不一致"
    [ "$STRICT" = 1 ] && { log "❌ REWRITE_STRICT=1，判失败"; exit 1; }
fi
url="${base}${path}"
host="${url#*://}"; host="${host%%/*}"
log "clone 目标: $url（对端 $host，形态 $MODE，次数 $ITER）"

case "$MODE" in
    full)    args=(--single-branch) ;;
    shallow) args=(--depth 1 --single-branch) ;;
    *) log "❌ 未知 CLONE_MODE=$MODE（可选 full|shallow）"; exit 1 ;;
esac

# run_clone <tag> <mode> <url> <dir>：计时并落一行 CSV
run_clone() {
    local tag="$1" mode="$2" u="$3" d="$4"
    local s e rc ms bytes mbps
    rm -rf "$d"
    s=$(date +%s%3N)
    if GIT_TERMINAL_PROMPT=0 git clone "${args[@]}" -q "$u" "$d" \
            >/dev/null 2>"$OUT/clone-$tag.err"; then
        rc=0
    else
        rc=$?
    fi
    e=$(date +%s%3N); ms=$((e - s))
    bytes=$(du -sb "$d" 2>/dev/null | cut -f1); bytes=${bytes:-0}
    mbps=$(awk -v b="$bytes" -v ms="$ms" 'BEGIN{ if (ms > 0) printf "%.2f", (b/1048576)/(ms/1000); else print "0.00" }')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "$mode" "$rc" "$ms" "$bytes" "$mbps" "$u" >> "$CSV"
    log "iter $tag ($mode): exit=$rc ${ms}ms $((bytes/1048576))MB ${mbps}MB/s"
    [ -f "$OUT/clone-$tag.err" ] && [ -s "$OUT/clone-$tag.err" ] && tail -n 3 "$OUT/clone-$tag.err" | sed 's/^/    | /'
    return "$rc"
}

# --- ② 基线（可选）：跳过全局 insteadOf，直接打上游 --------------------------
if [ "$BASELINE" = 1 ]; then
    uexp=$(GIT_CONFIG_GLOBAL=/dev/null git ls-remote --get-url "$REPO" 2>/dev/null)
    ubase=""
    case "$uexp" in
        *"$path") ubase=$(norm "${uexp%"$path"}") ;;
    esac
    if [ "$ubase" = "$origin" ]; then
        log "baseline: 直连上游 $origin（已跳过 insteadOf）"
        run_clone baseline baseline "$REPO" "$OUT/clone-baseline" || true
        rm -rf "$OUT/clone-baseline"
    else
        log "⚠️ 无法构建上游基线（GIT_CONFIG_GLOBAL=/dev/null 展开为 ${uexp:-<空>}），跳过"
    fi
fi

# --- ③ 主循环：同一仓库重复 clone ------------------------------------------
fails=0
for i in $(seq 1 "$ITER"); do
    run_clone "$i" "$MODE" "$url" "$OUT/clone-$i" || fails=$((fails + 1))
    rm -rf "$OUT/clone-$i"
done

# --- ④ 汇总：冷启动 vs 热路径（中位数），顺手出 markdown ----------------------
awk -F'\t' -v repo="$REPO" -v backend="$base" -v mode="$MODE" -v iter="$ITER" '
NR == 1 { next }
$1 == "baseline" { bl = $4; next }
{
    n++; ms[n] = $4; mb[n] = $6
    it[n] = $1; ex[n] = $3; by[n] = $5
    if (n == 1) cold = $4
    else { w++; warm[w] = $4 }
}
END {
    # 热路径中位数：冒泡排序（n 很小）
    for (i = 1; i <= w; i++)
        for (j = i + 1; j <= w; j++)
            if (warm[j] < warm[i]) { t = warm[i]; warm[i] = warm[j]; warm[j] = t }
    med = (w > 0) ? (w % 2 ? warm[(w+1)/2] : (warm[w/2] + warm[w/2+1]) / 2) : 0

    print "## gitcode clone 性能"
    print ""
    printf "- 仓库: `%s`\n", repo
    printf "- 后端: `%s`\n", backend
    printf "- 形态: `%s`，次数: %s（第 1 次冷启动）\n", mode, iter
    if (bl != "") printf "- 上游基线（直连 gitcode.com）: %d ms\n", bl
    print ""
    print "| 指标 | 耗时 |"
    print "|---|---|"
    printf "| 冷启动（第 1 次） | %d ms |\n", cold
    printf "| 热路径中位数（第 2..%d 次） | %d ms |\n", n, med
    if (cold > 0 && med > 0)
        printf "| 加速比 | %.2fx（%d ms → %d ms） |\n", cold/med, cold, med
    if (bl != "" && bl > 0 && med > 0)
        printf "| 相对上游 | %.2fx（上游 %d ms → 缓存 %d ms） |\n", bl/med, bl, med
    print ""
    print "| 次数 | exit | 耗时 | 大小 | 吞吐 |"
    print "|---|---|---|---|---|"
    for (i = 1; i <= n; i++)
        printf "| %s | %s | %d ms | %d MB | %s MB/s |\n", it[i], ex[i], ms[i], by[i]/1048576, mb[i]
    if (med > 0 && cold > 0 && med <= cold * 0.7)
        print "\n结论：热路径中位数 ≤ 冷启动 70%，缓存收益明显。"
    else
        print "\n结论：未见明显缓存收益（冷缓存首跑 / 后端不缓存该形态时属正常，仅留档）。"
}' "$CSV" > "$SUMMARY"

cat "$SUMMARY"
log "== 汇总（$CSV）=="
printf '%s\n' "iter	mode	exit	ms	bytes	MBps" >&2
awk -F'\t' 'NR>1{printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1,$2,$3,$4,$5,$6}' "$CSV" >&2

if [ "$fails" -gt 0 ]; then
    log "❌ 有 $fails 次 clone 失败（明细见 $OUT/clone-*.err）"
    exit 1
fi
log "完成。结果目录: $OUT"
