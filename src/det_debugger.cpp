/*
 * det_debugger.cpp — 检测项 2:调试器附加(含 IDA 动态调试)
 *
 * 原理:Android 上无论 gdb / lldb / IDA(android_server)还是 jdb,
 * 动态调试都绕不开 ptrace(PTRACE_ATTACH)。被附加的进程在
 * /proc/self/status 的 TracerPid 字段会留下跟踪者 pid——这是
 * 用户态反调试最硬的证据之一(要藏只能靠反反调试把自己从内核
 * 视图抹掉,难度远高于藏文件)。
 *
 * 辅助旁证:
 *   - IDA 的 android_server 默认监听 23946,gdbserver 常用 5039;
 *   - android_server 常驻 /data/local/tmp/android_server;
 *   - 调试器进程名。
 *
 * 局限:检测"当前此刻有没有被附加"。调试器可以在附加→读内存→
 * 摘除之间快速切换(TracerPid 只在该窗口非 0),所以产品里要
 * 周期轮询 + 与后续检测交错,而不是跑一次就完。
 */
#include "internal.h"

namespace sec {

class DebuggerDetector : public BaseDetector {
public:
    const char* name() const override { return "debugger"; }
    int type() const override { return DETECT_DEBUGGER; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);   /* input="pid:N" 扫目标进程,空=自己 */
        const char* who = (pid > 0) ? "debugger[pid]:" : "debugger:";

        /* 1) 内核记账:TracerPid 非 0 = 此刻正被某个进程 ptrace */
        int tp = util::tracer_pid_of(pid);
        if (tp > 0) {
            f.add("%s ptrace: TracerPid=%d", who, tp);
            risk = true;
        }

        /* 2) IDA android_server 特征 */
        if (util::path_exists("/data/local/tmp/android_server")) {
            f.add("ida: /data/local/tmp/android_server present");
            risk = true;
        }
        if (util::tcp_port_listening(23946)) {   // android_server 默认端口
            f.add("ida: android_server listening :23946");
            risk = true;
        }

        /* 3) gdbserver 常见端口(IDA 也可配置 gdb 模式走这里) */
        if (util::tcp_port_listening(5039)) {
            f.add("gdbserver: listening :5039");
            risk = true;
        }

        /* 4) 调试器进程名(android_server / gdbserver 常原样跑) */
        if (util::any_process_cmdline_contains("android_server")) {
            f.add("proc: android_server running");
            risk = true;
        }
        if (util::any_process_cmdline_contains("gdbserver")) {
            f.add("proc: gdbserver running");
            risk = true;
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_debugger_detector() {
    return new sec::DebuggerDetector();
}
