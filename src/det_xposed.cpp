/*
 * det_xposed.cpp — 检测项 4:Xposed / LSPosed / Riru / Zygisk 模块
 *
 * 原理:Xposed 家族(含 LSPosed)现在主流走 Zygisk/Riru 注入——
 * 模块 so 在 zygote 里被加载后,fork 出的每个 App 进程的 maps
 * 里都会带着模块映射(libxposed_art.so / liblspd.so / riru 等),
 * 这是"进程内注入"视角的铁证。系统级痕迹(框架 APK、模块目录)
 * 是第二类旁证。
 *
 * 局限:
 *   - 检测自身进程的 maps 只能发现"注入到我这个进程"的模块;
 *     若框架只 hook 别的进程,要遍历 /proc 下各 pid 的 maps(本骨架
 *     提供遍历进程 cmdline 的原语,产品可按需扩展成遍历各进程 maps);
 *   - 模块可改名、可把 so 拷进 /data/app 伪装;
 *   - Zygisk 本身是 Magisk 组件,与 root 检测重叠(已在 root 项
 *     记录 zygiskd)。
 */
#include "internal.h"

#include <unistd.h>

namespace sec {

class XposedDetector : public BaseDetector {
public:
    const char* name() const override { return "xposed"; }
    int type() const override { return DETECT_XPOSED; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        /* 1) 进程内注入:maps 映射名关键词 */
        static const char* kw[] = {
            "xposed", "lspd", "edxp", "riru", "zygisk",
            "tai-chi", "taichi",          // 太极(Tai-Chi)注入
            "dexposed",                   // 阿里开源的进程内 hook 框架
        };
        for (const char* k : kw) {
            if (util::self_maps_path_contains(k)) {
                f.add("maps: injected module '%s'", k);
                risk = true;
            }
        }

        /* 2) 老式系统级框架(ART 时代直接把 jar 塞进 framework) */
        if (util::file_exists("/system/framework/XposedBridge.jar")) {
            f.add("framework: /system/framework/XposedBridge.jar present");
            risk = true;
        }

        /* 3) root 权限下查模块目录与已装框架包 */
        if (geteuid() == 0) {
            std::vector<std::string> mods;
            util::list_dir("/data/adb/modules", mods);
            for (const auto& m : mods) {
                std::string low = m;
                for (auto& c : low) c = (char)tolower((unsigned char)c);
                if (low.find("lsposed") != std::string::npos ||
                    low.find("xposed") != std::string::npos ||
                    low.find("riru") != std::string::npos ||
                    low.find("tai") != std::string::npos) {
                    f.add("module: /data/adb/modules/%s", m.c_str());
                    risk = true;
                }
            }
        }

        /* 4) 已安装的框架管理器(pm 查询;慢,只作为补充路径。
         *    产品里应改为 Java 层 PackageManager 一次拿全量再过滤) */
        std::string pm = util::first_line_of(
            "pm list packages 2>/dev/null | grep -E -i 'xposed|lsposed|riru'");
        if (!pm.empty()) {
            f.add("pkg: %s", pm.c_str());
            risk = true;
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_xposed_detector() {
    return new sec::XposedDetector();
}
