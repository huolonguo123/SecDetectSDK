/*
 * det_root.cpp — 检测项 1:Root / Magisk
 *
 * 证据分级(由弱到强,命中任意一条即判风险):
 *   L1  su 二进制常见路径存在            —— 老式 root / SuperSU 残留
 *                                       (实测:Magisk 30 不在这些路径,仅兼容)
 *   L2  /debug_ramdisk/magisk 存在       —— Magisk 26+ 修补 boot 的载荷,
 *                                       非 root 也能 stat(实机验证命中)
 *       init.svc.magiskd=running         —— 仅 Magisk <26 走 init 服务时存在
 *   L3  root 权限下 /data/adb 特征        —— Magisk 安装目录、数据库(非 root 不可见)
 *
 * 局限(面试要能讲):su 改名/换路径可绕 L1;Magisk 的 DenyList 可以
 * 对白名单进程隐藏痕迹,但检测进程自身若非白名单,这些痕迹对 Magisk
 * 来说"没有隐藏的必要"。真正的强校验靠 TEE 的启动链证明
 * (boot state / dm-verity 状态,见 det_bootloader 与 TEE 占位)。
 * 另外注意:非 root 沙盒进程看不到 /data/adb(L3 失效),此时 L2 的
 * ramdisk 载荷是主证据——这也是把检测器放 App 里时的真实工作形态。
 */
#include "internal.h"

#include <unistd.h>

namespace sec {

class RootDetector : public BaseDetector {
public:
    const char* name() const override { return "root"; }
    int type() const override { return DETECT_ROOT; }
    bool needs_input() const override { return false; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        /* L1:su 二进制。F_OK 即可(只要求"路径上存在"),shell 权限够用 */
        static const char* su_paths[] = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/vendor/bin/su", "/su/bin/su", "/system/sbin/su",
            "/system/bin/.su", "/system/xbin/.su",   // 隐藏 dot 前缀形态
        };
        for (const char* p : su_paths) {
            if (util::file_exists(p)) {
                f.add("su binary: %s", p);
                risk = true;
            }
        }

        /* L2:boot ramdisk 里的 Magisk 载荷——非 root 也能 stat。
         *  Magisk 26+ 修补 boot 后把主二进制放在 /debug_ramdisk(early
         *  阶段就要执行);实机验证:目录对 other 开放 x(路径可穿透),
         *  文件 755 → 普通 shell 用精确路径 F_OK 即命中。这是新版
         *  Magisk 的硬痕迹,老式 SuperSU 反而没有。 */
        if (util::path_exists("/debug_ramdisk/magisk")) {
            f.add("magisk: /debug_ramdisk/magisk (patched boot ramdisk)");
            risk = true;
        }
        /* 老版本 Magisk(<26,守护进程注册为 init 服务)才有这个属性;
         *  Magisk 30 实测已无(见 det_root 头注释),保留仅为兼容旧机 */
        if (util::get_prop("init.svc.magiskd") == "running") {
            f.add("magiskd: init.svc.magiskd=running");
            risk = true;
        }

        /* L3:需要 euid==0 才能穿透 /data 的 SELinux 隔离 */
        if (geteuid() == 0) {
            static const char* data_adb_paths[] = {
                "/data/adb/magisk",        // Magisk 主目录
                "/data/adb/magisk.db",     // 数据库
                "/data/adb/magisk_patched",// 修补过的 boot 镜像备份
            };
            for (const char* p : data_adb_paths) {
                if (util::path_exists(p)) {
                    f.add("magisk data: %s", p);
                    risk = true;
                }
            }
            /* Magisk 模块目录下挂着 root 相关模块也计入 */
            std::vector<std::string> mods;
            util::list_dir("/data/adb/modules", mods);
            for (const auto& m : mods) {
                std::string low = m;
                for (auto& c : low) c = (char)tolower((unsigned char)c);
                if (low.find("magisk") != std::string::npos ||
                    low.find("riru") != std::string::npos) {
                    f.add("module: /data/adb/modules/%s", m.c_str());
                    risk = true;
                }
            }
        }

        /* 工程说明:不主动执行 su——弹授权框、可能挂起,SDK 不做副作用动作 */
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_root_detector() {
    return new sec::RootDetector();
}
