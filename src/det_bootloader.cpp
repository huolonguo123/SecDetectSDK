/*
 * det_bootloader.cpp — 检测项 8:Bootloader 解锁
 *
 * 原理:Android Verified Boot 链上,解锁的 bootloader 会在启动
 * 参数/内核 cmdline 里留下状态,最终以系统属性的形式暴露:
 *
 *   ro.boot.verifiedbootstate
 *       green  = 锁 + 完整验证链(安全)
 *       yellow = 锁但根证书是自定义的
 *       orange = 已解锁(user 固件,Magisk 刷机的前提)
 *       red    = 验证失败(坏镜像/被篡改)
 *   ro.boot.vbmeta.device_state   locked / unlocked
 *   ro.boot.flash.locked          1(锁) / 0(解锁)
 *   ro.secureboot.lockstate       MTK 平台的同义属性
 *
 * 为什么这对 App 重要:解锁是刷 Magisk、装 LSPosed、跑各种
 * hook 的地基——绝大多数真机作弊环境都要求 bootloader 解锁。
 * 检测到 orange + 其它风险项,作弊概率显著升高。
 *
 * 局限(重要):这些属性来自 bootloader 传递的 cmdline,但 root
 * 之后可以用 resetprop 伪造(getprop 读的是属性服务,不是硬件)。
 * 真正不可伪造的版本是 TEE 侧的 attestation / RPMB 存储状态
 * ——这正是设计文档里"bootloader 状态读取放 TEE"的原因,本项
 * 在用户态只能做到"读属性 + 交叉旁证",强校验留给 TEE 后端。
 */
#include "internal.h"

namespace sec {

class BootloaderDetector : public BaseDetector {
public:
    const char* name() const override { return "bootloader"; }
    int type() const override { return DETECT_BOOTLOADER; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

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

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_bootloader_detector() {
    return new sec::BootloaderDetector();
}
