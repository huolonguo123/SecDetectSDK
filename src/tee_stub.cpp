/*
 * tee_stub.cpp — TEE 扩展占位(后端注入点)
 *
 * 设计文档的承诺:bootloader 状态、磁盘 ELF 基线、opcode 摘要
 * 等"用户态可被注入篡改"的强校验,最终放在 TEE 安全世界:
 *
 *     普通侧 App ──(GP TEE client API)──► TA(安全世界)
 *                                            ├ 读 RPMB/OTP 的 boot 状态
 *                                            ├ 对磁盘 ELF 做基线哈希
 *                                            └ 出 attestation 结果
 *
 * 但写一个能跑的 TA 需要厂商签名与 TEE 厂商 SDK(高通/MTK),
 * 个人项目拿不到。所以本 SDK 把边界切在"后端抽象"上:
 *
 *   - secdetect_tee_set_backend(fn):集成方注入自己的 TA 通道
 *     (fn 内部做 GP client 调用,返回的数据写进 out);
 *   - secdetect_tee_attest():无后端时返回 1 并说明"未集成",
 *     有后端时透传后端结果(后端约定 0=通过)。
 *
 * 这样架构文档里的 TEE 部分有真实代码边界、可单测、可演示,
 * 且诚实标注"当前为占位"——简历/面试时不会被问穿。
 */
#include "internal.h"

namespace {

tee_attest_fn g_backend = nullptr;

const char* kNotIntegrated =
    "tee: TA channel not integrated (this is the user-space skeleton; "
    "implement tee_attest_fn over GlobalPlatform client and inject it)";

}  // namespace

extern "C" void secdetect_tee_set_backend(tee_attest_fn fn) {
    g_backend = fn;
}

extern "C" int secdetect_tee_attest(char* output, size_t output_len) {
    if (g_backend) {
        /* 后端自己处理 out 缓冲;约定:返回 0 = 数据已写入 */
        return g_backend(output, output_len);
    }
    if (output && output_len > 0) {
        size_t n = strlen(kNotIntegrated);
        if (n >= output_len) n = output_len - 1;
        memcpy(output, kNotIntegrated, n);
        output[n] = '\0';
    }
    return 1;   /* 未集成:1 = 环境无 TA,不是"检测到风险" */
}
