/*
 * det_bootloader.cpp — 检测项 8:Bootloader 解锁 + Google Key Attestation
 *
 * ============ 第一层:AVB 启动链属性(用户态可读,可被 resetprop 伪造) ============
 *   ro.boot.verifiedbootstate
 *       green  = 锁 + 完整验证链(安全)
 *       yellow = 锁但根证书是自定义的
 *       orange = 已解锁(user 固件,Magisk 刷机的前提)
 *       red    = 验证失败(坏镜像/被篡改)
 *   ro.boot.vbmeta.device_state   locked / unlocked
 *   ro.boot.flash.locked          1(锁) / 0(解锁)
 *   ro.boot.veritymode            enforcing / disabled(dm-verity 关闭)
 *   ro.secureboot.lockstate       MTK 平台同义属性
 *   ro.oem_unlock_allowed / sys.oem_unlock_allowed  允许 OEM 解锁
 *
 * 局限(关键):这些值来自 bootloader→cmdline→属性区,root 之后
 * resetprop 就能改。所以只查属性 = 只挡君子。
 *
 * ============ 第二层:Google Key Attestation(TEE 签名,伪造不了) ============
 * 原理:App 用 AndroidKeyStore 生成一个密钥,并带 setAttestationChallenge()
 * 申请「密钥证明」。TEE/StrongBox 会签发一张 X.509 证书,证书里
 * 有一段 ASN.1 的 attestation 扩展(KeyDescription),由**安全世界
 * 私钥签名**,内容包括:
 *
 *     attestationSecurityLevel      Software / TEE / StrongBox
 *     keymasterSecurityLevel        生成密钥时的安全级别
 *     verifiedBootState             Verified / SelfSigned / Unverified / Failed
 *     deviceLocked                  是否锁定(解锁 bootloader 会变 false)
 *     verifiedBootHash              当前启动链哈希
 *     osVersion / osPatchLevel      系统版本与补丁级别
 *
 * 这些字段由 TEE 签名,**用户态改不了**(改了就验签失败)。所以:
 *   - verifiedBootState != Verified  → 启动链没通过验证(解锁/自签/被改)
 *   - deviceLocked == false          → bootloader 解锁
 *   - securityLevel == Software      → 没有真正的安全世界(模拟器/被绕过)
 *   - verifiedBootHash 与官方不符    → 镜像被改
 *
 * ============ 第三层(本轮新增):验证侧 ============
 * 上面读到的字段"是不是真的",取决于有没有**验**:
 *   - java/…/KeyAttestationVerifier.java:逐级验签(leaf ← 中间 ← 根)+ 根信任锚
 *     + challenge 回验(证书里的 attestationChallenge == 本次下发的 nonce);
 *   - 结论以 att_chain_verified 回填:1 = 通过 / 0 = 失败 / -1 = 未知(没做自检);
 *   - KeyAttestation.java 支持 setChallenge(服务端一次性 nonce)、chainBase64()
 *     上报整条链(服务端验签的原料)、setVerifiedBootHashBaselineHex(比基线)。
 *
 * ★ 边界(别把 att_chain_verified==1 当成"不可伪造"):自检代码跑在攻击者机器上,
 *   Frida hook 掉 verify() 或 patch 返回值就能让它恒为 1。客户端自检只能"提高绕过
 *   成本";**权威判定必须在服务端**(服务端自己出 nonce、自己验链、自己比基线)。
 *
 * 本 SDK 不做 ASN.1 解析(native 侧零依赖),而是把解析结果作为
 * 「环境事实」回填进来 —— 由 java/…/KeyAttestation.java 生成并
 * 解析,再通过 secdetect_set_env_facts() 送进来。这样:
 *   1) 检测项只做判定,逻辑清晰;
 *   2) 集成方可以换成自研 TA(TEE 后端)实现,接口不变。
 */
#include "internal.h"

namespace sec {

class BootloaderDetector : public BaseDetector {
public:
    const char* name() const override { return "bootloader"; }
    int type() const override { return DETECT_BOOTLOADER; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        /* ---------- 第一层:AVB 属性 ---------- */
        std::string state = util::get_prop("ro.boot.verifiedbootstate");
        if (state == "orange" || state == "red" || state == "yellow") {
            f.add("vbstate: ro.boot.verifiedbootstate=%s", state.c_str());
            risk = true;
        }

        std::string dev = util::get_prop("ro.boot.vbmeta.device_state");
        if (dev == "unlocked") {
            f.add("vbmeta: ro.boot.vbmeta.device_state=unlocked");
            risk = true;
        }

        std::string locked = util::get_prop("ro.boot.flash.locked");
        if (locked == "0") {
            f.add("flash: ro.boot.flash.locked=0 (unlocked)");
            risk = true;
        }

        std::string mtk = util::get_prop("ro.secureboot.lockstate");
        if (mtk == "unlocked") {
            f.add("secureboot: ro.secureboot.lockstate=unlocked");
            risk = true;
        }

        std::string verity = util::get_prop("ro.boot.veritymode");
        if (verity == "disabled" || verity == "logging") {
            f.add("verity: ro.boot.veritymode=%s (dm-verity 未强制)", verity.c_str());
            risk = true;
        }

        std::string oem = util::get_prop("ro.oem_unlock_allowed");
        if (oem == "1") {
            f.add("oem: ro.oem_unlock_allowed=1 (允许解锁)");
            risk = true;
        }

        /* ---------- 第二层:Key Attestation(Java 回填) ---------- */
        if (!util::env_has(SEC_FACT_ATTESTATION)) {
            f.add("info: no key-attestation facts provided; call "
                  "secdetect_set_env_facts(facts.provided|=SEC_FACT_ATTESTATION) "
                  "from Java (see KeyAttestation.java) for the TEE-signed check");
        } else {
            const sec_env_facts_t& ef = util::env_facts();

            /* 安全级别:Software = 没有真正的 TEE(模拟器/被绕过) */
            std::string lvl = ef.att_security_level;
            if (!lvl.empty()) {
                std::string low = lvl;
                for (auto& c : low) c = (char)tolower((unsigned char)c);
                if (low.find("software") != std::string::npos) {
                    f.add("attest: securityLevel=%s (无硬件安全世界 → 可伪造)", lvl.c_str());
                    risk = true;
                } else {
                    f.add("attest: securityLevel=%s", lvl.c_str());
                }
            }

            if (ef.att_verified_boot_state == 2 || ef.att_verified_boot_state == 3 ||
                ef.att_verified_boot_state == 1) {
                static const char* st[] = {"Verified", "SelfSigned", "Unverified", "Failed"};
                int i = ef.att_verified_boot_state;
                f.add("attest: verifiedBootState=%s (非 Verified → 解锁/自签/被改)",
                      (i >= 0 && i <= 3) ? st[i] : "?");
                risk = true;
            }
            if (ef.att_device_locked == 0) {
                f.add("attest: deviceLocked=false (TEE 证明 bootloader 已解锁)");
                risk = true;
            }
            if (ef.att_verified_boot_hash_ok == 0) {
                f.add("attest: verifiedBootHash mismatch (启动链哈希与官方不符)");
                risk = true;
            }
            if (ef.att_sw_enforced == 1) {
                f.add("attest: software-enforced only (可被用户态改写)");
                risk = true;
            }
            if (ef.hw_backed_key == 0) {
                f.add("attest: 密钥非硬件支持 (isInsideSecureHardware=false)");
                risk = true;
            }

            /* ---------- 验证侧:客户端自检的链验证结论 ----------
             * 1 = 逐级验签 + 根信任锚 + challenge 回验都通过(仍然是客户端自检,可被 hook)
             * 0 = 验证失败 → 证书不是给定根签发的、或 challenge 不匹配(伪造/重放强信号)
             * -1 = 没做自检(缺 nonce 或缺根信任锚)→ 不判,只当未知 */
            if (ef.att_chain_verified == 0) {
                f.add("attest: **证书链验证失败** —— 非给定根签发 / challenge 不匹配"
                      "(伪造或重放的强信号;服务端应据此拒绝)");
                risk = true;
            } else if (ef.att_chain_verified == 1) {
                f.add("attest: chain verified(客户端自检:逐级验签 + challenge 回验通过;"
                      "权威判定仍应在服务端)");
            }
            if (ef.att_os_version[0])
                f.add("attest: %s", ef.att_os_version);
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_bootloader_detector() {
    return new sec::BootloaderDetector();
}
