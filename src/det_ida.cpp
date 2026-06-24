/*
 * det_ida.cpp — 检测项 12:IDA Pro 调试服务(android_server / dbgsrv)
 *
 * 为什么和"调试器"分项:IDA 的移动端调试链路有自己的指纹,且
 * 是中文逆向圈最常被滥用的一条(android_server + IDA 远程调试):
 *
 *   host(IDA) ──tcp:23946──► device: /data/local/tmp/android_server
 *                                   └─ ptrace(PTRACE_ATTACH) 到目标进程
 *
 * 证据分四层(从"落地物"到"行为"):
 *   1) 落盘物:/data/local/tmp/android_server{,64,32}、dbgsrv 目录、
 *      ida 相关文件 —— IDA 部署时基本原样放,名字很少改;
 *   2) 进程:cmdline/comm 为 android_server* / idat64 / ida64 的进程;
 *   3) 端口:默认 23946(改端口也躲不过"谁在监听"的归属反查);
 *   4) 归属:TracerPid 指向的那个进程 cmdline 里就是 android_server
 *      —— 这是"IDA 正在调我"的直接证据;
 *   5) 内存:目标进程 maps / 字符串里出现 android_server 相关特征
 *      (比如 IDA 用 gdb 模式或 loader 注入时留下的名字)。
 */
#include "internal.h"

namespace sec {

namespace {

const char* kIdaProcessNames[] = {
    "android_server",      /* IDA 官方调试服务(默认 23946)   */
    "android_server64",
    "android_server32",
    "ida_server",
    "idat",                /* IDA text-mode(host 侧,交叉旁证) */
    "idat64",
    "ida64",
    "idal",                /* IDA lite                        */
};

const char* kIdaFiles[] = {
    "/data/local/tmp/android_server",
    "/data/local/tmp/android_server64",
    "/data/local/tmp/android_server32",
    "/data/local/tmp/ida_server",
    "/data/local/tmp/idaserver",
    "/data/local/tmp/.ida",
    "/data/local/tmp/ida",
    "/data/local/tmp/dbgsrv",
};

/* IDA 默认调试端口;23947/23948 是常见的连号备用 */
const uint16_t kIdaPorts[] = {23946, 23947, 23948};

std::string cmdline_first(int pid) {
    std::string s = util::proc_read(pid, "cmdline");
    for (auto& c : s) if (c == '\0') c = ' ';
    size_t e = s.find_last_not_of(' ');
    if (e != std::string::npos) s.erase(e + 1);
    if (s.size() > 80) s.erase(80);
    return s;
}

bool mentions_ida(const std::string& s) {
    return s.find("android_server") != std::string::npos ||
           s.find("ida_server") != std::string::npos ||
           s.find("/ida") != std::string::npos ||
           s.find("idat") != std::string::npos;
}

}  // namespace

class IdaDetector : public BaseDetector {
public:
    const char* name() const override { return "ida"; }
    int type() const override { return DETECT_IDA; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);
        const char* who = (pid > 0) ? "ida[pid]:" : "ida:";

        /* 1) 落盘物:android_server 本体与 dbgsrv 目录 */
        for (const char* p : kIdaFiles)
            if (util::path_exists(p)) {
                f.add("file: %s", p);
                risk = true;
            }
        std::vector<std::string> dbgsrv;
        util::list_dir("/data/local/tmp/dbgsrv", dbgsrv);
        for (const auto& e : dbgsrv) {
            f.add("file: /data/local/tmp/dbgsrv/%s", e.c_str());
            risk = true;
        }

        /* 2) 进程名(全量名单) */
        std::vector<util::ProcHit> hits;
        for (const char* n : kIdaProcessNames) {
            size_t before = hits.size();
            util::find_processes(n, hits, 8);
            for (size_t i = before; i < hits.size(); ++i) {
                f.add("proc: %s (pid=%d) \"%s\"", n, hits[i].pid,
                      hits[i].cmdline.empty() ? hits[i].comm.c_str() : hits[i].cmdline.c_str());
                risk = true;
            }
        }

        /* 3) 端口 + 归属反查 */
        std::vector<util::ListenPort> ports;
        util::list_listening_ports(ports);
        for (const auto& lp : ports) {
            bool named = mentions_ida(lp.owner);
            bool known = false;
            for (uint16_t p : kIdaPorts) if (p == lp.port) known = true;
            if (named) {
                f.add("tcp: ida server port %u owner=[%s] pid=%d", lp.port,
                      lp.owner.c_str(), lp.pid);
                risk = true;
            } else if (known) {
                f.add("tcp: IDA default debug port %u listening (owner=%s)", lp.port,
                      lp.owner.empty() ? "?" : lp.owner.c_str());
                risk = true;
            }
        }

        /* 4) 归属:TracerPid 指向 android_server = IDA 正在调我 */
        int tp = util::tracer_pid_of(pid);
        if (tp > 0) {
            std::string tr = cmdline_first(tp);
            if (mentions_ida(tr)) {
                f.add("%s tracer pid %d is IDA: \"%s\"", who, tp, tr.c_str());
                risk = true;
            }
        }

        /* 5) 内存特征:目标进程 maps / 字符串里出现 android_server */
        if (util::maps_path_contains(pid, "android_server")) {
            f.add("%s maps: android_server module mapped", who);
            risk = true;
        }
        uint64_t at = 0;
        std::string region;
        if (util::mem_scan_string(pid, "/data/local/tmp/android_server", 24ULL * 1024 * 1024,
                                  &at, &region)) {
            f.add("%s mem: string \"/data/local/tmp/android_server\" @0x%llx (%s)",
                  who, (unsigned long long)at, region.empty() ? "anon" : region.c_str());
            risk = true;
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_ida_detector() {
    return new sec::IdaDetector();
}
