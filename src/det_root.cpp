/*
 * det_root.cpp — 检测项 1:Root / Magisk(含"已隐藏 root"场景的检测)
 *
 * ================== 为什么会有"隐藏 root"这一节 ==================
 * Magisk 的 DenyList(旧称 MagiskHide)会对被勾选的进程做「挂载点
 * 摘除」:在该进程的 mount namespace 里把 magisk 的挂载卸掉,并
 * 用 bind mount 把原始文件还原。于是**文件层的一切特征都看不见了**:
 *   ls /system/bin/su → 不存在
 *   /proc/self/mountinfo 里没有 magisk
 *   maps 里也没有 magisk
 * 只做"扫文件/扫路径"的 root 检测在这种情况下会全部落空。
 *
 * 检测"隐藏后的 root",思路必须换维度:
 *
 *   A) 属性维度(最实用):DenyList 隐藏的是「文件与挂载」,不隐藏
 *      「系统属性区」。而且属性区可以**全量枚举**(__system_property_foreach),
 *      所以任何 magisk/zygisk/riru/kernelsu/apatch 相关的 property
 *      (不管名字怎么起、值是什么)都看得见 —— 这就是本项的 A 组证据。
 *
 *   B) 命名空间差分(最硬的逻辑证据):Magisk 只在「目标进程的
 *      namespace」里卸载挂载,init(pid 1)的 namespace 里那些挂载
 *      依然在。所以拿 /proc/self/mountinfo 和 /proc/1/mountinfo
 *      对差:init 有、我没有 = 有东西"专门为我卸掉了"。
 *      这是"你隐藏了"这件事本身留下的痕迹(需要 root 才能读 pid 1)。
 *
 *   C) 启动链维度:bootloader 解锁状态(ro.boot.verifiedbootstate=orange、
 *      ro.boot.flash.locked=0、ro.boot.vbmeta.device_state=unlocked)
 *      来自 bootloader 传给内核的 cmdline,不经文件系统,DenyList
 *      也挡不住;resetprop 能伪造但它同时会留下"属性区被改过"的
 *      破绽(配对 B 组使用)。解锁是刷 Magisk 的前提,单独看是旁证,
 *      和 A/B 一起看就构成完整证据链。
 *
 *   D) SELinux 域:进程自身的 SELinux context 若是 u:r:magisk:s0 /
 *      u:r:su:s0(sh 提权后常见),直接命中。
 *
 * ================== 命中分级 ==================
 *   L1 su 二进制常见路径(老式 root,兼容用)
 *   L2 boot ramdisk 载荷 /debug_ramdisk/magisk(Magisk 26+,非 root 可见)
 *   L3 属性枚举 + 关键属性(DenyList 隐藏不掉)
 *   L4 mount namespace 差分 + mountinfo 异常挂载
 *   L5 SELinux 域 / SELinux 强制状态
 *   L6 /data/adb 及模块目录(需 root)
 *   L7 启动链属性(解锁状态,旁证/交叉)
 *
 * 局限:resetprop 能删/改属性(A 组可被针对性清除);KernelSU/APatch
 * 是内核态实现,用户态痕迹更少,主要靠 B/C 组。真正的强校验是
 * TEE 侧的 attestation(见 bootloader 项与 Key Attestation)。
 */
#include "internal.h"

#include <unistd.h>

#include <set>

namespace sec {

namespace {

/* 关键词 → 命中说明(属性/挂载点/maps 三处共用) */
struct RootKeyword {
    const char* kw;
    const char* what;
};
const RootKeyword kRootKw[] = {
    {"magisk",    "magisk"},
    {"zygisk",    "zygisk(Magisk 模块注入)"},
    {"kernelsu",  "KernelSU"},
    {"ksud",      "KernelSU 守护进程"},
    {"apatch",    "APatch"},
    {"apd",       "APatch 守护进程"},
    {"riru",      "Riru"},
    {"supersu",   "SuperSU 残留"},
    {"busybox",   "busybox"},
};

std::string lower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

/* 从 mountinfo 一行里取挂载点(field[4]) */
std::string mount_point_of(const std::string& line) {
    size_t i = 0;
    int f = 0;
    while (f < 4) {
        size_t b = line.find_first_not_of(' ', i);
        if (b == std::string::npos) return {};
        size_t e = line.find(' ', b);
        i = (e == std::string::npos) ? line.size() : e;
        ++f;
    }
    size_t b = line.find_first_not_of(' ', i);
    if (b == std::string::npos) return {};
    size_t e = line.find(' ', b);
    return line.substr(b, (e == std::string::npos) ? std::string::npos : e - b);
}

/* 从 mountinfo 行里取 fstype("-" 之后的第一个字段) */
std::string fstype_of(const std::string& line) {
    size_t dash = line.find(" - ");
    if (dash == std::string::npos) return {};
    size_t b = line.find_first_not_of(' ', dash + 3);
    if (b == std::string::npos) return {};
    size_t e = line.find(' ', b);
    return line.substr(b, (e == std::string::npos) ? std::string::npos : e - b);
}

void collect_mount_points(const std::string& info, std::set<std::string>& out) {
    const char* p = info.c_str();
    while (p && *p) {
        const char* eol = strchr(p, '\n');
        std::string line(p, eol ? (size_t)(eol - p) : strlen(p));
        p = eol ? eol + 1 : nullptr;
        std::string mp = mount_point_of(line);
        if (!mp.empty()) out.insert(mp);
    }
}

}  // namespace

class RootDetector : public BaseDetector {
public:
    const char* name() const override { return "root"; }
    int type() const override { return DETECT_ROOT; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);

        /* ---------------- L1:su 二进制路径 ---------------- */
        static const char* su_paths[] = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/sbin/.su",
            "/vendor/bin/su", "/su/bin/su", "/system/sbin/su", "/system/bin/.su",
            "/system/xbin/.su", "/debug_ramdisk/su", "/system/bin/failsafe/su",
            "/data/local/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/magisk/.core/bin/su",
        };
        for (const char* p : su_paths)
            if (util::file_exists(p)) {
                f.add("L1 su binary: %s", p);
                risk = true;
            }

        /* ---------------- L2:boot ramdisk 里的 Magisk 载荷 ----------------
         * Magisk 26+ 把主二进制放 /debug_ramdisk(Magisk 可能在此路径
         * 被 DenyList 摘除;命中说明没被隐藏或隐藏不彻底) */
        static const char* magisk_paths[] = {
            "/debug_ramdisk/magisk", "/debug_ramdisk/.magisk",
            "/sbin/.magisk", "/dev/.magisk", "/cache/magisk.log",
            "/data/magisk", "/magisk", "/data/.magisk",
        };
        for (const char* p : magisk_paths)
            if (util::path_exists(p)) {
                f.add("L2 magisk payload: %s", p);
                risk = true;
            }

        /* ---------------- L3:属性维度(DenyList 隐藏不掉) ---------------- */
        if (util::get_prop("init.svc.magiskd") == "running") {
            f.add("L3 magiskd: init.svc.magiskd=running");
            risk = true;
        }
        /* 全量属性枚举:任何名字/值里带 root 工具关键词的属性都报出来。
         * 这是"隐藏 root"下最值的检查 —— 属性区不参与 mount 隐藏。 */
        std::vector<std::pair<std::string, std::string>> props;
        util::enumerate_props(props, 4096);
        std::set<std::string> seen_note;
        for (const auto& kv : props) {
            std::string low = lower(kv.first + "=" + kv.second);
            for (const RootKeyword& k : kRootKw) {
                if (k.kw[0] == '\0') continue;
                if (low.find(k.kw) == std::string::npos) continue;
                if (!seen_note.insert(k.what).second) continue;   /* 同类只报一条 */
                f.add("L3 prop[%s]: %s (=> %s)", k.what, kv.first.c_str(), kv.second.c_str());
                risk = true;
            }
        }

        /* ---------------- L4:mount namespace 差分 + 异常挂载 ---------------- */
        std::string selfinfo = util::proc_read(pid, "mountinfo");
        if (!selfinfo.empty()) {
            std::set<std::string> self_mp;
            collect_mount_points(selfinfo, self_mp);

            /* 4a) 挂载行里直接出现关键词(未隐藏时会命中) */
            const char* p = selfinfo.c_str();
            while (p && *p) {
                const char* eol = strchr(p, '\n');
                std::string line(p, eol ? (size_t)(eol - p) : strlen(p));
                p = eol ? eol + 1 : nullptr;
                std::string low = lower(line);
                for (const RootKeyword& k : kRootKw) {
                    if (k.kw[0] && low.find(k.kw) != std::string::npos) {
                        f.add("L4 mountinfo '%s': %s", k.what, line.c_str());
                        risk = true;
                        break;
                    }
                }
            }

            /* 4b) overlay/tmpfs 挂在系统目录上(真机 /system 是
             *     erofs/ext4/只读 bind;Magisk 用 tmpfs 覆写 /system/bin
             *     来注入 su/zygisk) */
            p = selfinfo.c_str();
            int odd = 0;
            while (p && *p && odd < 4) {
                const char* eol = strchr(p, '\n');
                std::string line(p, eol ? (size_t)(eol - p) : strlen(p));
                p = eol ? eol + 1 : nullptr;
                std::string ft = fstype_of(line);
                if (ft != "tmpfs" && ft != "overlay") continue;
                std::string mp = mount_point_of(line);
                if (mp.rfind("/system", 0) == 0 || mp.rfind("/vendor", 0) == 0 ||
                    mp.rfind("/product", 0) == 0 || mp == "/") {
                    f.add("L4 %s on %s (magisk-style overlay/tmpfs)", ft.c_str(), mp.c_str());
                    risk = true;
                    ++odd;
                }
            }

            /* 4c) 与 init(pid 1)的 namespace 差分:init 有、我没有 =
             *     有挂载被"专门为我"卸掉了(Magisk DenyList 的痕迹)。
             *     读 /proc/1/mountinfo 需要 root。 */
            std::string initinfo = util::proc_read(1, "mountinfo");
            if (!initinfo.empty() && pid <= 0) {
                std::set<std::string> init_mp;
                collect_mount_points(initinfo, init_mp);
                int hidden = 0;
                std::string names;
                for (const auto& mp : init_mp) {
                    if (self_mp.count(mp)) continue;
                    ++hidden;
                    if (hidden <= 4) names += (names.empty() ? "" : ",") + mp;
                }
                if (hidden > 0) {
                    f.add("L4 hidden mounts: init has %d mount(s) this process "
                          "cannot see (%s) — Magisk DenyList unmount signature",
                          hidden, names.c_str());
                    risk = true;
                }
            } else if (initinfo.empty() && pid <= 0) {
                f.add("L4 note: /proc/1/mountinfo unreadable (no root) — "
                      "namespace diff skipped");
            }
        }

        /* ---------------- L5:SELinux 域 ---------------- */
        std::string ctx = util::proc_read(pid, "attr/current");
        if (ctx.find("magisk") != std::string::npos ||
            ctx.find(":su:") != std::string::npos ||
            ctx.find("supersu") != std::string::npos) {
            f.add("L5 selinux domain: %s", ctx.c_str());
            risk = true;
        }

        /* ---------------- L6:/data/adb(需 root) ---------------- */
        if (geteuid() == 0) {
            static const char* data_adb_paths[] = {
                "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk_patched",
                "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ap", "/data/adb/apd",
                "/data/adb/zygisk", "/data/adb/lspd", "/data/adb/modules_update",
            };
            for (const char* pth : data_adb_paths)
                if (util::path_exists(pth)) {
                    f.add("L6 magisk data: %s", pth);
                    risk = true;
                }
            std::vector<std::string> mods;
            util::list_dir("/data/adb/modules", mods);
            for (const auto& m : mods) {
                std::string low = lower(m);
                for (const RootKeyword& k : kRootKw) {
                    if (k.kw[0] && low.find(k.kw) != std::string::npos) {
                        f.add("L6 module: /data/adb/modules/%s", m.c_str());
                        risk = true;
                        break;
                    }
                }
            }
        }

        /* ---------------- L7:启动链(解锁=刷 Magisk 的前提,旁证) ---------------- */
        std::string vb = util::get_prop("ro.boot.verifiedbootstate");
        std::string locked = util::get_prop("ro.boot.flash.locked");
        if (vb == "orange" || vb == "red" || locked == "0") {
            f.add("L7 boot chain: verifiedbootstate=%s flash.locked=%s "
                  "(unlocked — root/Magisk 前提;DenyList 隐藏不掉)",
                  vb.empty() ? "?" : vb.c_str(), locked.empty() ? "?" : locked.c_str());
            risk = true;
        }

        /* 工程说明:不主动执行 su——弹授权框、可能挂起,SDK 不做副作用动作 */
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_root_detector() {
    return new sec::RootDetector();
}
