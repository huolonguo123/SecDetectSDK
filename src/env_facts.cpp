/*
 * env_facts.cpp — 环境事实回填区(Java/JNI -> native 的单向数据通道)
 *
 * 为什么需要这一层:
 *   USB 调试开关、USB 物理连接、传感器数量、GL_RENDERER、
 *   以及 Google Key Attestation 的结果,普通 native 进程根本拿不到
 *   (要走 Context/Settings/UsbManager/SensorManager/KeyStore)。
 *   设计上没有让检测项去猜,而是开一个显式的"事实回填"口:
 *
 *     Java(UsbState/KeyAttestation/...)
 *          │  fill sec_env_facts_t
 *          ▼
 *     JNI bridge (jni/sec_jni.cpp) → secdetect_set_env_facts()
 *          │
 *          ▼
 *     native 检测项 (usb_debug / bootloader / emulator / vm) 读 util::env_facts()
 *
 * provided 位图保证"没回填的字段不会被当成 0 误报"。
 */
#include "internal.h"

namespace sec {
namespace util {

namespace {
sec_env_facts_t g_facts;   // 零初始化 → provided = 0,所有字段 = 未知
}  // namespace

const sec_env_facts_t& env_facts() { return g_facts; }

void set_env_facts(const sec_env_facts_t* f) {
    if (!f) return;
    g_facts = *f;
    /* 防御性修正:provided 之外的字段保持未知语义 */
    if (!env_has(SEC_FACT_ATTESTATION)) {
        g_facts.att_verified_boot_state = -1;
        g_facts.att_device_locked = -1;
        g_facts.att_verified_boot_hash_ok = -1;
        g_facts.att_sw_enforced = -1;
        g_facts.att_chain_verified = -1;
        g_facts.att_os_version[0] = '\0';
        g_facts.att_security_level[0] = '\0';
    }
    if (!env_has(SEC_FACT_GL_RENDERER)) g_facts.gl_renderer[0] = '\0';

    /* 未置位的标量字段同样必须回到"未知"(-1)。
     * 之前漏了 hw_backed_key:集成方不走 JNI、直接填结构体时如果不置 SEC_FACT_HW_KEY
     * (字段留 0),第 8 项会把它当成"非硬件密钥"→ **误报风险**。
     * 这里的契约是"provided 位图之外的字段一律未知",所以逐个补上。 */
    if (!env_has(SEC_FACT_HW_KEY)) g_facts.hw_backed_key = -1;
    if (!env_has(SEC_FACT_APK_PATH)) g_facts.apk_path[0] = '\0';
    if (!env_has(SEC_FACT_APK_BASELINE)) g_facts.apk_baseline[0] = '\0';
}

bool env_has(uint32_t bit) { return (g_facts.provided & bit) != 0; }

}  // namespace util
}  // namespace sec

extern "C" SEC_API void secdetect_set_env_facts(const sec_env_facts_t* facts) {
    sec::util::set_env_facts(facts);
}

extern "C" SEC_API void secdetect_get_env_facts(sec_env_facts_t* out) {
    if (out) *out = sec::util::env_facts();
}
