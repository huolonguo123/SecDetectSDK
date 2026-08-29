/*
 * det_module.cpp — 检测项 10:非白名单可执行模块(白名单差分)
 *
 * 与 frida/xposed 的"黑名单关键词"思路相反:这里不认识任何
 * 可疑名字,而是列出进程所有可执行映射,与"合法集合"做差分。
 * 注入者把 so 改名成 libhappy.so、拷到任意目录都绕不掉
 * "这个代码不是已安装 App/系统的"这一事实。
 *
 * 检测目标:input 传 "pid:1234" 扫别的进程(需 root/同 uid,
 * SELinux 会挡跨 uid 读 /proc);不传/传空 = 扫自己。
 *
 * 合法集合(白名单):
 *   1) 系统目录:/system /apex /vendor /odm /product /system_ext,
 *      以及 /data/dalvik-cache(App 进程必映射 boot.oat,系统生成);
 *   2) /data/app/ 前缀:所有已安装 App 的 native lib 与 oat
 *      都从这里加载 —— 对任意目标进程这都是"正常的 so 来源";
 *   3) 目标进程主程序 exe(读 /proc/<pid>/exe),精确白名单;
 *   4) /dev/__properties__(bionic 属性共享内存,每进程必映射,看着
 *      像陌生可执行映射实则是系统机制)。
 *
 * 额外一类硬证据:带 " (deleted)" 的可执行映射 ——
 *   "写临时文件 → mmap → unlink"是经典注入手法,文件系统里查不到
 *   任何文件,只有 maps 留痕。**这类映射无条件报**(即便路径在白名单里)。
 *
 * 局限(面试要能讲):
 *   - 只看得到"有路径名"的映射;纯匿名内存加载(mmap 匿名 + 写代码
 *     再执行)在 maps 里是 [anon:...],要 opcode/特征扫描兜底
 *     (第 3 项 frida 的 [anon]/[memfd] 组已经覆盖这部分);
 *   - 路径白名单假设系统目录与 /data/app 可信;root 往 /system
 *     或已装 App 目录塞 so 可绕,产品要对关键目录叠哈希/签名;
 *   - 扫别人进程需要 root:App 沙盒内只能查自己,这正是 SDK
 *     集成进被保护 App 后查自身 maps 的产品形态。
 */
#include "internal.h"

namespace sec {

namespace {

bool is_trusted_path(const std::string& p, const std::string& exe) {
    static const char* kTrusted[] = {
        "/system/", "/apex/", "/vendor/", "/odm/", "/product/", "/system_ext/",
        "/data/dalvik-cache/",   /* boot.oat 等系统编译产物 */
        "/data/app/",            /* 已安装 App 的 lib/oat 加载点 */
        "/dev/__properties__/",  /* bionic 属性共享内存(每进程必映射) */
        "/data/misc/",           /* 系统服务加载点 */
    };
    for (const char* s : kTrusted)
        if (p.compare(0, strlen(s), s) == 0) return true;
    /* 目标主程序自身(eg: runner 在 /data/local/tmp 下跑,它自己得白) */
    if (!exe.empty() && p == exe) return true;
    return false;
}

}  // namespace

class ModuleDetector : public BaseDetector {
public:
    const char* name() const override { return "module"; }
    int type() const override { return DETECT_MODULE; }

    bool run(const char* input, Findings& f) override {
        int pid = util::target_pid(input);
        std::vector<util::MapRegion> maps;
        if (!util::parse_maps(pid, maps)) {
            if (pid > 0 && !util::process_exists(pid))
                f.add("module: no such process pid %d", pid);
            else
                f.add("module: cannot read maps for pid %d "
                      "(permission denied, need root)", pid);
            return false;
        }
        std::string exe = util::exe_of(pid);
        const char* who = (pid > 0) ? "module[pid]:" : "module:";

        bool risk = false;
        int shown = 0;
        for (const auto& r : maps) {
            if (!r.is_exec()) continue;
            if (r.anonymous()) continue;          /* [anon:..]/[vdso] 无身份可查 */

            /* (deleted) 的可执行映射:无条件报(注入手法) */
            if (r.deleted) {
                if (shown++ < 8)
                    f.add("%s deleted exec map: %s (mmap→unlink injection)",
                          who, r.path.c_str());
                risk = true;
                continue;
            }
            if (is_trusted_path(r.path, exe)) continue;

            if (shown++ < 8)
                f.add("%s unexpected exec map: %s", who, r.path.c_str());
            risk = true;
        }
        if (shown > 8) f.add("%s ... %d more unexpected exec maps", who, shown - 8);
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_module_detector() {
    return new sec::ModuleDetector();
}
