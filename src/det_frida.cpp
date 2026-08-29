/*
 * det_frida.cpp — 检测项 3:Frida 注入 / frida-server / **魔改版**
 *
 * ==================== 正常 frida 的形态 ====================
 *   A) frida-server(独立进程,root 手机常用)
 *      - 进程 cmdline 含 frida / frida-helper / linjector;
 *      - 默认监听 27042(新版随机端口 → 用"归属进程反查"兜住);
 *      - Magisk 模式会在 /data/local/tmp 留 socket re.frida.server。
 *   B) frida-gadget / 注入 agent(进目标进程)
 *      - 目标进程 maps 里出现 frida-agent-*.so / frida-gadget.so / linjector;
 *      - 新版本用 memfd_create 注入 → maps 里是 "/memfd:frida-agent-64.so";
 *      - 线程名:gum-js-loop / gmain / gdbus / pool-frida;
 *      - 内存里能找到 "frida:rpc"、gum 的符号/字符串。
 *
 * ==================== 魔改版 frida(strongR 等)====================
 * 魔改的目标就是"不让你按名字找到它",它们的改法本身 = 检测点:
 *
 *   1) 改 "frida:rpc" 字符串  → 常见做法是换成 base64('frida:rpc')
 *      = "ZnJpZGE6cnBj";也可能换成短随机串。
 *      ★ 所以特征表里同时放明文与 base64 两种 needle。
 *   2) 改 agent 模块名(frida-agent → 随机名),甚至不落盘,用 memfd:
 *      ★ 检测点就变成"匿名可执行映射"与"/memfd:"映射,
 *        不再依赖名字(见 memfd / anon-exec 两组)。
 *   3) 改线程名(gum-js-loop → 改名/不命名):
 *      ★ 检测点变成"无名字/gum 变体线程" + JIT 特征内存。
 *   4) 保留 gum(JS 引擎)的符号/字符串 —— 改这个成本高,所以
 *      ★ "gum-js-loop"/"gum_module_load"/"GumScript" 这类字符串
 *        是魔改版最经得住的特征,保留在 needle 表里。
 *
 * 本项落到 8 组证据,全部命中都输出:
 *   [proc]  frida-server 系进程          [port] 端口+归属反查
 *   [file]  /data/local/tmp 落盘物       [maps] 模块名特征
 *   [memfd] memfd 注入映射(匿名注入)   [anon] 可疑匿名可执行段
 *   [thread] 线程名特征                  [scan] 内存字符串(含 base64 魔改特征)
 *
 * 局限:魔改版可以连 gum 字符串一起加密(那就只剩"匿名可执行+memfd+
 * 行为"这类结构性特征);对抗升级是持续过程,特征表要跟着版本迭代。
 */
#include "internal.h"

namespace sec {

namespace {

/* 进程名/命令行关键词(frida-server 侧) */
const char* kFridaProcs[] = {
    "frida", "frida-server", "frida-helper", "linjector", "re.frida",
};

/* maps 模块名特征(注入侧) */
const char* kFridaModules[] = {
    "frida",            /* frida-agent.so / frida-agent-64.so / frida-gadget.so */
    "libfrida",
    "linjector",        /* frida 的注入器                          */
    "gum-js",           /* gum JS 运行时                            */
    "gum_js",
    "re.frida",
    "frida_agent",
    ".frida",
    "gadget",           /* frida-gadget(注意:通用词,命中单独标注) */
};

/* 线程名特征 */
const char* kFridaThreads[] = {
    "gum-js-loop",      /* frida 的 JS 线程(最经典)          */
    "gum-js",
    "gmain",            /* glib 主循环(frida 用 glib)        */
    "gdbus",            /* glib dbus 线程                    */
    "pool-frida",
    "frida",
    "linjector",
};

/* 落盘物 */
const char* kFridaFiles[] = {
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida-server",
    "/data/local/tmp/frida-server-16.0.0",
    "/data/local/tmp/frida-gadget.so",
    "/data/local/tmp/frida-agent.so",
    "/data/local/tmp/linjector",
    "/data/local/tmp/frida",
};

/* ★ 内存特征表(明文 + 魔改 base64 变体),一次扫完 */
const char* kFridaNeedles[] = {
    "frida:rpc",                 /* frida 的 RPC 握手字符串(明文)          */
    "ZnJpZGE6cnBj",              /* base64("frida:rpc") —— 魔改版常用替换   */
    "frida-agent",               /* agent 模块名/字符串                     */
    "frida_agent_main",          /* agent 入口符号                          */
    "frida-gadget",              /* gadget 模块名                           */
    "ZnJpZGEtZ2FkZ2V0",          /* base64("frida-gadget")                  */
    "gum-js-loop",               /* gum JS 线程名(魔改版常保留)           */
    "gum_module_load",           /* gum 符号(改名成本高)                   */
    "GumScript",                 /* gum 的 JS 脚本类                        */
    "gum_script_backend",
};

/* 匿名可执行段的"已知合法"标记(Android 运行时常态,不算注入) */
const char* kAnonSafe[] = {
    "dalvik", "jit", "libc_malloc", "scudo", "linker", "asan",
    "stack_and_tls", "cfi", "art", "vvar", "vdso", "vectors",
    "sigpage", "memtag", "madvise", "gpu", "sgm", "hwui", "skia",
};

bool anon_label_is_known_safe(const std::string& label) {
    std::string low = label;
    for (auto& c : low) c = (char)tolower((unsigned char)c);
    for (const char* s : kAnonSafe)
        if (low.find(s) != std::string::npos) return true;
    return false;
}

void lower_inplace(std::string& s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
}

}  // namespace

class FridaDetector : public BaseDetector {
public:
    const char* name() const override { return "frida"; }
    int type() const override { return DETECT_FRIDA; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);   /* input="pid:N" 扫目标进程,空=自己 */
        const char* who = (pid > 0) ? "frida[pid]:" : "frida:";

        /* ---------- [proc] frida-server 系进程 ---------- */
        std::vector<util::ProcHit> hits;
        for (const char* n : kFridaProcs) {
            size_t before = hits.size();
            util::find_processes(n, hits, 8);
            for (size_t i = before; i < hits.size(); ++i) {
                f.add("[proc] %s (pid=%d) \"%s\"", n, hits[i].pid,
                      hits[i].cmdline.empty() ? hits[i].comm.c_str() : hits[i].cmdline.c_str());
                risk = true;
            }
        }

        /* ---------- [port] 默认端口 + 归属反查(随机端口也抓) ---------- */
        std::vector<util::ListenPort> ports;
        util::list_listening_ports(ports);
        for (const auto& lp : ports) {
            std::string low = lp.owner;
            lower_inplace(low);
            bool named = low.find("frida") != std::string::npos ||
                         low.find("linjector") != std::string::npos ||
                         low.find("gadget") != std::string::npos;
            bool def = (lp.port == 27042 || lp.port == 27043);
            if (named) {
                f.add("[port] %u owner=[%s] pid=%d (frida server)", lp.port,
                      lp.owner.c_str(), lp.pid);
                risk = true;
            } else if (def) {
                f.add("[port] default frida port %u listening (owner=%s)", lp.port,
                      lp.owner.empty() ? "?" : lp.owner.c_str());
                risk = true;
            }
        }

        /* ---------- [file] 落盘物 ---------- */
        for (const char* p : kFridaFiles)
            if (util::path_exists(p)) {
                f.add("[file] %s", p);
                risk = true;
            }

        /* ---------- [maps] 模块名特征 ---------- */
        for (const char* k : kFridaModules)
            if (util::maps_path_contains(pid, k)) {
                f.add("%s [maps] injected module contains '%s'", who, k);
                risk = true;
            }

        /* ---------- [memfd] / [anon] 结构化特征(不依赖名字) ---------- */
        std::vector<util::MapRegion> maps;
        if (util::parse_maps(pid, maps)) {
            int memfd = 0, anon = 0, rwx = 0;
            for (const auto& r : maps) {
                if (!r.is_exec()) continue;
                /* memfd 注入:写临时/内存文件 → mmap → 执行,frida 新版与
                 * 各类 loader 都爱用;maps 里路径是 "/memfd:xxx" */
                if (r.path.rfind("/memfd:", 0) == 0) {
                    if (memfd < 3) f.add("%s [memfd] %s exec map (memfd injection)", who, r.path.c_str());
                    ++memfd;
                    risk = true;
                }
                /* 临时文件 mmap 后 unlink 的可执行映射(注入手法,文件系统
                 * 无痕,maps 里带 (deleted) 标记) */
                if (r.deleted) {
                    if (anon < 3)
                        f.add("%s [anon] deleted exec map: %s (mmap→unlink injection)", who, r.path.c_str());
                    ++anon;
                    risk = true;
                }
                /* 伪文件系统里的可执行映射 */
                if (r.path.rfind("/proc/self/fd/", 0) == 0) {
                    if (anon < 3) f.add("%s [anon] suspicious exec map: %s", who, r.path.c_str());
                    ++anon;
                    risk = true;
                }
                /* 匿名可执行段:排除 dalvik/jit 等运行时常态 */
                if (r.anonymous()) {
                    std::string label = r.path.empty() ? "[anon:unnamed]" : r.path;
                    if (!anon_label_is_known_safe(label)) {
                        if (anon < 4)
                            f.add("%s [anon] unexpected anon exec map: %s (0x%llx-0x%llx)",
                                  who, label.c_str(), (unsigned long long)r.start,
                                  (unsigned long long)r.end);
                        ++anon;
                        risk = true;
                    }
                }
                /* rwx 段:JIT 常态之外,几乎只有注入器会要 */
                if (r.is_write() && r.is_read() && r.is_exec()) {
                    if (rwx < 3)
                        f.add("%s [anon] rwx map: %s 0x%llx-0x%llx",
                              who, r.path.empty() ? "[anon]" : r.path.c_str(),
                              (unsigned long long)r.start, (unsigned long long)r.end);
                    ++rwx;
                    risk = true;
                }
            }
            if (anon > 4) f.add("[anon] ... %d more unexpected/anon exec maps", anon - 4);
        }

        /* ---------- [thread] 线程名特征 ---------- */
        std::vector<std::string> comms;
        util::list_thread_comms(pid, comms);
        for (const auto& c : comms) {
            std::string low = c;
            lower_inplace(low);
            for (const char* t : kFridaThreads) {
                if (low.find(t) != std::string::npos) {
                    f.add("%s [thread] %s", who, c.c_str());
                    risk = true;
                    break;
                }
            }
        }

        /* ---------- [scan] 内存字符串(明文 + 魔改 base64) ---------- */
        const char* hit = nullptr;
        uint64_t at = 0;
        std::string region;
        if (util::mem_scan_any(pid, kFridaNeedles, sizeof(kFridaNeedles) / sizeof(*kFridaNeedles),
                               24ULL * 1024 * 1024, &hit, &at, &region)) {
            f.add("%s [scan] mem hit \"%s\" @0x%llx (%s)%s", who, hit ? hit : "?",
                  (unsigned long long)at, region.empty() ? "anon" : region.c_str(),
                  (hit && hit[0] == 'Z') ? " [base64-modified frida]" : "");
            risk = true;
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_frida_detector() {
    return new sec::FridaDetector();
}
