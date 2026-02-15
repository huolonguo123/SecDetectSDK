/*
 * det_usb.cpp — 检测项 9:USB 调试
 *
 * 原理:USB 调试开着 = adbd 在跑 = 具备 adb 提权/抓包/动态调试
 * 的通道。对生产 App 而言这是基础风险面(即使没 root,adb 也
 * 能 backup、monkey 注入、抓取日志)。
 *
 * 证据:
 *   - persist.sys.usb.config / sys.usb.config 含 "adb":当前 USB
 *     功能配置里挂着 adb(典型值 "mtp,adb");
 *   - ro.debuggable=1:eng/userdebug 固件,adbd 默认 root 运行
 *     且 ro.secure=0,是重打包/测试固件的标志;
 *   - 5555 端口监听:网络 adb(tcpip 模式),比 USB 更危险
 *     (局域网内任何人有密码就能连)。
 *
 * 局限:sys.usb.config 反映"功能开关",与"此刻有没有数据线连着"
 * 是两回事;产品里可再叠加 Settings.Global adb_enabled(需读
 * settings provider)与 /proc/net 的连接状态判断当前活跃会话。
 */
#include "internal.h"

namespace sec {

class UsbDebugDetector : public BaseDetector {
public:
    const char* name() const override { return "usb_debug"; }
    int type() const override { return DETECT_USB_DEBUG; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        auto config_has_adb = [&](const char* prop) {
            std::string cfg = util::get_prop(prop);
            if (cfg.find("adb") != std::string::npos) {
                f.add("usb: %s=%s (adb enabled)", prop, cfg.c_str());
                risk = true;
            }
        };
        config_has_adb("persist.sys.usb.config");
        config_has_adb("sys.usb.config");
        /* 旧设备/部分厂商 */
        std::string mtp = util::get_prop("persist.sys.usb.charging");
        (void)mtp;

        std::string dbg = util::get_prop("ro.debuggable");
        if (dbg == "1") {
            f.add("rom: ro.debuggable=1 (eng/userdebug build)");
            risk = true;
        }

        if (util::tcp_port_listening(5555)) {
            f.add("adb: network adb listening :5555");
            risk = true;
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_usb_detector() {
    return new sec::UsbDebugDetector();
}
