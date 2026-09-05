/* native_attest_smoke.cpp — 第 8 项「验证侧」判定的开发期冒烟测试(不需要 Android 设备)
 *
 * 为什么能脱离设备跑:
 *   det_bootloader.cpp 只依赖 internal.h 里的 util::get_prop / util::env_has /
 *   util::env_facts;其中 env_facts 是本项目自带的纯 C++(src/env_facts.cpp),
 *   只有 __system_property_get 那一层要 Android —— 这里用桩替掉(第一层 AVB 属性
 *   不是本测试的对象,本测试只验"验证侧结论怎么影响判定")。
 *
 * 编译运行:
 *   g++ -std=c++17 -Iinclude -Isrc tools/native_attest_smoke.cpp \
 *       src/det_bootloader.cpp src/env_facts.cpp -o /tmp/attest_smoke && /tmp/attest_smoke
 *
 * 覆盖四组:
 *   A att_chain_verified=-1(未做自检)  → 不出链相关行,不判风险
 *   B att_chain_verified=1(自检通过)    → 打印 "chain verified",不判风险
 *   C att_chain_verified=0(自检失败)    → **判风险**(字段看着是"已锁定"也没用)
 *   D 字段本身有问题(deviceLocked=0/Unverified) → 仍按原逻辑判风险
 */
#include "internal.h"

#include <cstdio>
#include <cstring>

/* ---- 桩:替换 util.cpp 中的 Android 属性读取 ---- */
namespace sec {
namespace util {
std::string get_prop(const char* /*name*/) { return std::string(); }
}  // namespace util
}  // namespace sec

using namespace sec;

static int g_fail = 0;

static void run_case(const char* title, int chainVerified, int deviceLocked, int vbs,
                     const char* secLevel, int expectRisk, const char* expectSubstr) {
    sec_env_facts_t f;
    memset(&f, 0, sizeof f);
    f.provided = SEC_FACT_ATTESTATION;          /* 模拟 Java 回填了 attestation */
    f.att_verified_boot_state = vbs;
    f.att_device_locked = deviceLocked;
    f.att_verified_boot_hash_ok = -1;           /* 没基线 → 未知 */
    f.att_sw_enforced = 0;
    f.att_chain_verified = chainVerified;
    snprintf(f.att_security_level, sizeof f.att_security_level, "%s", secLevel);
    snprintf(f.att_os_version, sizeof f.att_os_version, "Android 13 patch 2024-01");
    secdetect_set_env_facts(&f);

    BaseDetector* d = sec_make_bootloader_detector();
    Findings fd;
    const bool risk = d->run(nullptr, fd);
    delete d;

    const bool substrOk = (expectSubstr == nullptr) || (strstr(fd.c_str(), expectSubstr) != nullptr);
    const bool pass = (risk == (expectRisk != 0)) && substrOk;

    printf("%s %-52s risk=%d(期望 %d) 期望含「%s」:%s\n", pass ? "[PASS]" : "[FAIL]", title,
           (int)risk, expectRisk, expectSubstr ? expectSubstr : "(不检查)",
           substrOk ? "命中" : "**没找到**");
    printf("       证据: %s\n", fd.empty() ? "(空)" : fd.c_str());
    if (!pass) ++g_fail;
}

int main() {
    printf("=== 第 8 项 验证侧冒烟测试(不需要设备)===\n");
    run_case("A 未做自检(chain=-1),字段已锁定",
             /*chain*/ -1, /*locked*/ 1, /*vbs*/ 0, "TEE", /*risk*/ 0, nullptr);
    run_case("B 自检通过(chain=1),字段已锁定",
             1, 1, 0, "TEE", 0, "chain verified");
    run_case("C **自检失败(chain=0),但字段看着是'已锁定'**",
             0, 1, 0, "TEE", 1, "证书链验证失败");
    run_case("D 字段本身有问题(deviceLocked=0 / Unverified)",
             1, 0, 2, "TEE", 1, "deviceLocked=false");
    run_case("E 软件安全级别(Software → 无真 TEE)",
             1, 1, 0, "Software", 1, "securityLevel=Software");

    printf("\n%s\n", g_fail == 0 ? "全部通过" : "有用例失败");
    return g_fail == 0 ? 0 : 1;
}
