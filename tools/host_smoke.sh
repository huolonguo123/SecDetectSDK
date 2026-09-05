#!/bin/bash
# host_smoke.sh — 不需要设备的宿主冒烟:整库编一份再真跑(推手机前的快速回归)
#
# 原理:全项目只有一处 Android 专有依赖(src/util.cpp 的 sys/system_properties.h),
# 用 tools/host-shim 里的桩把它替掉,其余(调度/参数校验/repack 多路径/12 项注册表)
# 都是 Linux 通用逻辑,可以直接在 WSL 里跑。
#
# 用法:bash tools/host_smoke.sh          (在项目根目录执行)
# 退出码:0 = 全部用例符合预期;非 0 = 有用例失败
#
# 注意:属性相关的检测项在宿主上必然报 clean/unknown(属性读取是桩)——
#       这**不是** bug,宿主版只用来验解析/调度/参数逻辑。
set -u
cd "$(dirname "$0")/.." || exit 1

OUT=${TMPDIR:-/tmp}/secdetect_host
echo "=== 1) 编宿主版 ==="
g++ -std=c++17 -O1 -I tools/host-shim -Iinclude -Isrc src/*.cpp demo/main.cpp -o "$OUT" || exit 1
echo "  产物: $OUT ($(ls -la "$OUT" | awk '{print $5}') 字节)"

# CLI 退出码映射:SDK 的 SEC_ERR_PARAM(-1) → 进程码 2;SEC_OK(0)/SEC_RISK(1) 原样(见 demo/main.cpp)
TOUCH_A=/tmp/smoke_a.apk
TOUCH_B=/tmp/smoke_b.apk
: > "$TOUCH_A"; : > "$TOUCH_B"
CRLF=$(printf '%s\r\n | %s ' "$TOUCH_A" "$TOUCH_B")

FAIL=0
check() { # $1=说明 $2=期望退出码 $3...=参数
  local desc=$1 want=$2; shift 2
  "$OUT" "$@" > /tmp/smoke_out.txt 2>&1; local rc=$?
  if [ "$rc" = "$want" ]; then
    printf '  [PASS] %-40s rc=%s\n' "$desc" "$rc"
  else
    printf '  [FAIL] %-40s rc=%s(期望 %s)\n' "$desc" "$rc" "$want"
    sed -n '1,3p' /tmp/smoke_out.txt | sed 's/^/         /'
    FAIL=$((FAIL+1))
  fi
}

echo "=== 2) repack(第 7 项)参数校验:multi-path ==="
check "单路径(存在)→ 通过"              0 7 "$TOUCH_A"
check "多路径(都存在)→ 通过"            0 7 "$TOUCH_A|$TOUCH_B"
check "多路径(第 2 个不存在)→ 拦下"      2 7 "$TOUCH_A|/tmp/definitely_missing.apk"
check "单路径(不存在)→ 拦下"             2 7 "/tmp/definitely_missing.apk"
check "带 CRLF/空格的路径 → 通过"         0 7 "$CRLF"
check "空 input → 走 env facts 自动模式(rc=0,由 Java 回填路径)" 0 7 ""

echo "=== 3) 第 3 项不得自命中(自身 needle 常量在 .rodata 里)==="
"$OUT" 3 > /tmp/smoke_frida.txt 2>&1
if grep -q 'scan. mem hit' /tmp/smoke_frida.txt; then
  printf '  [FAIL] 扫自己命中了自身特征常量(needle 自命中误报)\n'
  grep 'scan. mem hit' /tmp/smoke_frida.txt | sed 's/^/         /'
  FAIL=$((FAIL+1))
else
  printf '  [PASS] 第 3 项未出现 [scan] mem hit(自身模块已排除)\n'
fi

echo "=== 4) 全项扫描能跑完(12 项一行一条)==="
"$OUT" all > /tmp/smoke_all.txt 2>&1
LINES=$(grep -c '^[0-9]*|' /tmp/smoke_all.txt)
if [ "$LINES" -ge 12 ]; then
  printf '  [PASS] all 输出 %s 行检测结果\n' "$LINES"
else
  printf '  [FAIL] all 只输出 %s 行(期望 ≥12)\n' "$LINES"; FAIL=$((FAIL+1))
fi
sed -n '1,14p' /tmp/smoke_all.txt | sed 's/^/         /'

echo
if [ "$FAIL" = 0 ]; then echo "宿主冒烟全部通过"; else echo "有 $FAIL 个用例失败"; fi
exit $FAIL
