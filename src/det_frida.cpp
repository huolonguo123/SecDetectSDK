/*
 * det_frida.cpp — 检测项 3:Frida 注入 / frida-server 驻留
 *
 * Frida 两种形态,证据各不同:
 *
 *   A) frida-server(独立进程,root 手机常用):
 *      - 进程 cmdline 含 "frida"(frida-server-<ver> 原样);
 *      - 默认监听 27042(tcp);新版本随机端口,所以端口只是旁证;
 *      - Magisk 模式起服务时会在 /data/local/tmp 留 socket 文件
 *        re.frida.server。
 *
 *   B) frida-gadget / 注入 agent(进目标进程):
 *      - 进程自身 maps 里出现 frida-agent-*.so / frida-gadget.so
 *        / linjector 映射 —— 这是"有人往我肚子里塞了代码"的铁证,
 *        因为正常系统库和自身 so 里不可能出现这些名字。
 *
 * 局限:注入者可以 1) 改 so 文件名;2) 把 agent 拷进 /data 下
 * 伪装;3) 用反射内存加载(不落盘、不进 maps 路径名)。所以单项
 * 证据都可被针对性绕过,产品里还要叠内存特征扫描(opcode/
 * gum 字符串)与行为检测(线程名 gum-js-loop、端口探测)。
 */
#include "internal.h"

namespace sec {

class FridaDetector : public BaseDetector {
public:
    const char* name() const override { return "frida"; }
    int type() const override { return DETECT_FRIDA; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        /* A1:进程级驻留 */
        if (util::any_process_cmdline_contains("frida")) {
            f.add("proc: frida-server process running");
            risk = true;
        }
        /* A2:默认端口(老版本固定 27042) */
        if (util::tcp_port_listening(27042)) {
            f.add("tcp: frida default port 27042 listening");
            risk = true;
        }
        /* A3:Magisk 模式 socket 文件 */
        if (util::path_exists("/data/local/tmp/re.frida.server")) {
            f.add("sock: /data/local/tmp/re.frida.server present");
            risk = true;
        }

        /* B:注入自己进程的映射(命中=最直接证据) */
        static const char* kw[] = {"frida", "linjector", "gadget"};
        for (const char* k : kw) {
            if (util::self_maps_path_contains(k)) {
                f.add("maps: injected module contains '%s'", k);
                risk = true;
            }
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_frida_detector() {
    return new sec::FridaDetector();
}
