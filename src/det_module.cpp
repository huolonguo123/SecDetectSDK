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
 *   1) 系统目录:/system /apex /vendor /odm /product,
 *      以及 /data/dalvik-cache(App 进程必映射 boot.oat,系统生成);
 *   2) /data/app/ 前缀:所有已安装 App 的 native lib 与 oat
 *      都从这里加载 —— 对任意目标进程这都是"正常的 so 来源";
 *   3) 目标进程主程序 exe(读 /proc/<pid>/exe),精确白名单。
 *
 * 局限(面试要能讲):
 *   - 只看得到"有路径名"的映射;纯匿名内存加载(mmap 匿名 +
 *     写代码再执行)在 maps 里是 [anon:...],无路径可查,要
 *     opcode/特征扫描兜底;
 *   - 路径白名单假设系统目录与 /data/app 可信;root 往 /system
 *     或已装 App 目录塞 so 可绕,产品要对关键目录叠哈希/签名
 *     (即上 TEE 的那部分);
 *   - 扫别人进程需要 root:App 沙盒内只能查自己,这正是 SDK
 *     集成进被保护 App 后查自身 maps 的产品形态。
 */
#include "internal.h"

namespace sec {

namespace {

bool has_exec(const char* perms) {
    return perms && strchr(perms, 'x') != nullptr;
}

bool is_trusted_path(const std::string& p, const std::string& exe) {
    static const char* kTrusted[] = {
        "/system/", "/apex/", "/vendor/", "/odm/", "/product/",
        "/data/dalvik-cache/",   /* boot.oat 等系统编译产物 */
        "/data/app/",            /* 已安装 App 的 lib/oat 加载点 */
        "/dev/__properties__/",  /* bionic 属性共享内存(每进程必映射) */
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
        std::string maps = util::maps_of(pid);
        if (maps.empty()) {
            f.add("module: cannot read maps for pid %d "
                  "(need root to scan other processes)", pid);
            return false;
        }
        std::string exe = util::exe_of(pid);
        const char* who = (pid > 0) ? "module[pid]:" : "module:";

        bool risk = false;
        const char* p = maps.c_str();
        while (p && *p) {
            const char* eol = strchr(p, '\n');
            std::string line(p, eol ? eol - p : strlen(p));
            p = eol ? eol + 1 : nullptr;

            /* 行:start-end perms offset dev inode pathname
             * 跳 5 个空白分隔字段,perms 是第 2 个,path 是剩余整段 */
            const char* perms = nullptr;
            int fields = 0;
            const char* t = line.c_str();
            while (fields < 5 && *t) {
                while (*t == ' ') ++t;
                if (!*t) break;
                if (fields == 1) perms = t;
                const char* sp = strchr(t, ' ');
                if (!sp) break;
                t = sp;
                ++fields;
            }
            while (*t == ' ') ++t;

            /* 只关心可执行映射,且必须带路径名(匿名映射无身份可查) */
            if (!has_exec(perms) || !*t) continue;

            std::string path(t);
            auto d = path.find(" (deleted)");
            if (d != std::string::npos) path.erase(d);
            if (path.empty() || path[0] == '[') continue;   /* [anon:..]/[vdso] */

            if (is_trusted_path(path, exe)) continue;

            f.add("%s unexpected exec map: %s", who, path.c_str());
            risk = true;
        }
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_module_detector() {
    return new sec::ModuleDetector();
}
