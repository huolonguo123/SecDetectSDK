/*
 * det_debugger.cpp — 检测项 2:调试器附加(ptrace)
 *
 * 原理:Android 上无论 gdb / lldb / IDA(android_server)/ jdb / jdwp,
 * 动态调试都绕不开 ptrace(PTRACE_ATTACH)。被附加的进程在
 * /proc/self/status 的 TracerPid 字段会留下跟踪者 pid——这是
 * 用户态反调试最硬的证据之一(要藏只能靠反反调试把自己从内核
 * 视图抹掉,难度远高于藏文件)。
 *
 * 本项只做「通用调试器」:IDA 的 android_server 有独立检测项
 * (第 12 项 DETECT_IDA),Frida 有第 3 项;这里覆盖:
 *
 *   1) 内核记账:TracerPid / 进程状态 't'(被 ptrace 停住)
 *   2) 调试器进程名单(全量列出,不再只查 gdb)
 *   3) 调试端口 + **归属进程反查**(端口号可以改,归属者名字难改)
 *   4) /data/local/tmp 下的调试器落盘物
 *   5) Java 调试:maps 里出现 libjdwp.so = JDWP 已开启
 *
 * 局限:只抓"当前此刻"的附加状态;调试器可在 attach→读内存→摘除
 * 之间快速切换(TracerPid 只在该窗口非 0),产品要周期轮询。
 */
#include "internal.h"

namespace sec {

namespace {

/* 通用调试器进程名/命令行关键词(全量列出来,方便对着日志核对) */
const char* kDebuggerNames[] = {
    "gdb",            /* GNU debugger                                  */
    "gdbserver",      /* gdb 远程调试服务端(常被 IDA 的 gdb 模式用)     */
    "gdbserver64",
    "lldb",           /* LLVM debugger                                 */
    "lldb-server",    /* lldb 远程服务端(Android Studio LLDB)         */
    "debugserver",    /* Apple/lldb 系                                 */
    "jdb",            /* Java debugger                                 */
    "jdwp",           /* Java Debug Wire Protocol(Java 调试通道)       */
    "radare2",        /* radare2 / rizin 系(注意别用两字母 r2,易误报) */
    "rizin",
    "strace",         /* syscall tracer                                */
    "ltrace",
    "frida",          /* (第 3 项专查,这里只作为交叉旁证)               */
    "android_server", /* (第 12 项专查,这里只作为交叉旁证)               */
    "gcore", "valgrind",
};

/* 常见调试端口(端口可改,所以只当旁证;真正靠归属进程名) */
const uint16_t kDebugPorts[] = {5039, 1234, 31337, 2159};

/* /data/local/tmp 下调试器的落盘物 */
const char* kDebugFiles[] = {
    "/data/local/tmp/gdbserver", "/data/local/tmp/gdbserver64",
    "/data/local/tmp/lldb-server", "/data/local/tmp/gdb",
    "/data/local/tmp/debugserver", "/data/local/tmp/strace",
};

std::string cmdline_first(int pid) {
    std::string s = util::proc_read(pid, "cmdline");
    for (auto& c : s) if (c == '\0') c = ' ';
    size_t e = s.find_last_not_of(' ');
    if (e != std::string::npos) s.erase(e + 1);
    if (s.size() > 80) s.erase(80);
    return s;
}

}  // namespace

class DebuggerDetector : public BaseDetector {
public:
    const char* name() const override { return "debugger"; }
    int type() const override { return DETECT_DEBUGGER; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);   /* input="pid:N" 扫目标进程,空=自己 */
        const char* who = (pid > 0) ? "debugger[pid]:" : "debugger:";

        /* 1) 内核记账:TracerPid 非 0 = 此刻正被某个进程 ptrace。
         *    顺手把它是谁读出来(cmdline),归属清楚才能定性。 */
        int tp = util::tracer_pid_of(pid);
        if (tp > 0) {
            std::string tr = cmdline_first(tp);
            if (tr.empty())
                f.add("%s ptrace: TracerPid=%d", who, tp);
            else
                f.add("%s ptrace: TracerPid=%d tracer=\"%s\"", who, tp, tr.c_str());
            risk = true;
        }

        /* 2) 进程状态 't' = 被 ptrace 停住(断点命中/单步窗口) */
        std::string stat = util::proc_read(pid, "stat");
        size_t rp = stat.rfind(')');
        if (rp != std::string::npos && rp + 2 < stat.size()) {
            char st = stat[rp + 2];
            if (st == 't' || st == 'T') {
                f.add("%s state=%c (stopped by ptrace/debugger)", who, st);
                risk = true;
            }
        }

        /* 3) 调试器进程名单(全量) */
        std::vector<util::ProcHit> hits;
        for (const char* n : kDebuggerNames) {
            size_t before = hits.size();
            util::find_processes(n, hits, 12);
            for (size_t i = before; i < hits.size(); ++i) {
                f.add("proc: %s (pid=%d) \"%s\"", n, hits[i].pid,
                      hits[i].cmdline.empty() ? hits[i].comm.c_str() : hits[i].cmdline.c_str());
                risk = true;
            }
        }

        /* 4) 监听端口 + 归属进程反查:改端口也躲不过"谁在监听" */
        std::vector<util::ListenPort> ports;
        util::list_listening_ports(ports);
        for (const auto& lp : ports) {
            bool named = false;
            for (const char* n : kDebuggerNames)
                if (lp.owner.find(n) != std::string::npos) named = true;
            bool known_port = false;
            for (uint16_t p : kDebugPorts) if (p == lp.port) known_port = true;
            if (named) {
                f.add("tcp: dbg port %u owner=[%s] pid=%d", lp.port,
                      lp.owner.c_str(), lp.pid);
                risk = true;
            } else if (known_port) {
                f.add("tcp: known debug port %u listening (owner=%s)", lp.port,
                      lp.owner.empty() ? "?" : lp.owner.c_str());
                risk = true;
            }
        }

        /* 5) 落盘物 */
        for (const char* p : kDebugFiles)
            if (util::file_exists(p)) {
                f.add("file: %s", p);
                risk = true;
            }

        /* 6) Java 调试:libjdwp.so 被映射 = JDWP 通道已打开 */
        if (util::maps_path_contains(pid, "libjdwp.so")) {
            f.add("%s jdwp: libjdwp.so mapped (Java debugging enabled)", who);
            risk = true;
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_debugger_detector() {
    return new sec::DebuggerDetector();
}
