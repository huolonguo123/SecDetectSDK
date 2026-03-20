/*
 * det_module.cpp — 检测项 10:非白名单可执行模块(白名单差分)
 *
 * 与 frida/xposed 的"黑名单关键词"思路相反:这里不认识任何
 * 可疑名字,而是列出自身进程所有可执行映射,与"合法集合"
 * 做差分——不在系统库目录、也不属于自身的可执行文件 = 可疑。
 * 注入者把 so 改名成 libhappy.so、拷到任意目录都绕不掉
 * "这个代码不是我 APK 里的"这一事实。
 *
 * 合法集合:
 *   1) 系统目录:/system /apex /vendor /odm /product,
 *      以及 /data/dalvik-cache(App 进程必映射 boot.oat,系统生成);
 *   2) 自身模块(so 形态,路径含 "/lib/"):白名单 = 整个 App
 *      安装目录前缀 —— 该目录下 lib/ 与 oat/ 都是自己 APK
 *      解压/编译的产物;
 *   3) 自身模块(exe 形态,runner):精确白名单自身这一个文件。
 *
 * 局限(面试要能讲):
 *   - 只看得到"有路径名"的映射;纯匿名内存加载(mmap 匿名 +
 *     写代码再执行)在 maps 里是 [anon:...],无路径可查,要
 *     opcode/特征扫描兜底;
 *   - 路径白名单假设系统目录可信;root 往 /system 塞 so 可绕,
 *     产品要对关键目录叠哈希/签名(即上 TEE 的那部分);
 *   - 只查自身进程:真实 App 场景 = SDK 集成进被保护 App 后
 *     查自己,这正是交付 libsecsdk.so 而不是 runner 的原因。
 */
#include "internal.h"

#include <dlfcn.h>
#include <unistd.h>

namespace sec {

namespace {

bool has_exec(const char* perms) {
    return perms && strchr(perms, 'x') != nullptr;
}

bool is_system_path(const std::string& p) {
    static const char* kSys[] = {
        "/system/", "/apex/", "/vendor/", "/odm/", "/product/",
        "/data/dalvik-cache/",
    };
    for (const char* s : kSys)
        if (p.compare(0, strlen(s), s) == 0) return true;
    return false;
}

/* 本检测代码所在模块的绝对路径:库形态 = libsecsdk.so,
 * runner 形态 = 可执行文件本身(dladdr 按地址范围定位对象)。 */
std::string self_module_path() {
    Dl_info di;
    if (dladdr(reinterpret_cast<void*>(&sec_make_module_detector), &di) &&
        di.dli_fname && di.dli_fname[0] == '/') {
        return di.dli_fname;
    }
    char buf[512];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        return buf;
    }
    return {};
}

bool is_own(const std::string& p, const std::string& own,
            const std::string& own_prefix) {
    if (own.empty()) return false;
    if (!own_prefix.empty())
        return p.compare(0, own_prefix.size(), own_prefix) == 0;
    return p == own;   /* exe 形态:只白自身一个文件 */
}

}  // namespace

class ModuleDetector : public BaseDetector {
public:
    const char* name() const override { return "module"; }
    int type() const override { return DETECT_MODULE; }

    bool run(const char*, Findings& f) override {
        std::string maps;
        if (!util::read_small_file("/proc/self/maps", maps)) {
            f.add("module: cannot read /proc/self/maps");
            return false;
        }

        /* 自身定位:so 形态(路径含 /lib/)→ 白整个 App 安装目录
         * (lib 与 oat 都是自己 APK 的产物);exe 形态 → 白一个文件 */
        std::string own = self_module_path();
        std::string own_prefix;
        size_t lib = own.find("/lib/");
        if (lib != std::string::npos)
            own_prefix = own.substr(0, lib + 1);   /* ".../<pkg>/" */

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

            if (is_system_path(path) || is_own(path, own, own_prefix))
                continue;

            f.add("module: unexpected exec map: %s", path.c_str());
            risk = true;
        }
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_module_detector() {
    return new sec::ModuleDetector();
}
