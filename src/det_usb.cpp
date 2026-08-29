/*
 * det_usb.cpp — 检测项 9:USB 调试 / 开发选项 / 物理 USB 连接
 *
 * 这一项要把三件**很容易混淆**的事分开(面试常问):
 *
 *   1) "USB 数据线插着吗?"      —— 硬件事实
 *      查法:native 读内核 sysfs(/sys/class/power_supply/usb/online、
 *      /sys/class/android_usb/android0/state),或 Java 的 UsbManager /
 *      ACTION_BATTERY_CHANGED。**不依赖 adb 开关。**
 *
 *   2) "USB 调试(ADB)开着吗?"   —— 系统设置项
 *      native 拿不到(要 Context + Settings.Global),所以由 Java
 *      读 Settings.Global.ADB_ENABLED / DEVELOPMENT_SETTINGS_ENABLED,
 *      JNI 回填(SEC_FACT_ADB_ENABLED)。这是"调试通道是否打开"。
 *
 *   3) "adbd 真的在跑吗?"       —— 进程/端口事实
 *      persist.sys.usb.config/sys.usb.config 含 "adb"、5555 端口监听
 *      (网络 adb,tcpip 模式)、ro.debuggable=1(eng/userdebug 固件)。
 *
 * 也就是说:native 侧能独立完成的只有 1 和 3;**2 必须 Java**——
 * 这正是本 SDK 设计"环境事实回填"通道的原因(见 sec_detect_api.h)。
 *
 * 局限:sys.usb.config 反映"功能开关"而非"此刻有没有会话";
 * 5555 只在 tcpip 模式下监听。产品里可叠加 adb 授权公钥
 * (/data/misc/adb/adb_keys,需 root)与 dumpsys 会话状态。
 */
#include "internal.h"

namespace sec {

class UsbDebugDetector : public BaseDetector {
public:
    const char* name() const override { return "usb_debug"; }
    int type() const override { return DETECT_USB_DEBUG; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        /* ---------- 1) 物理 USB 连接(native sysfs,不依赖 Java) ---------- */
        int usb = util::usb_physically_connected();
        if (usb == 1) {
            std::string on = util::read_line_file("/sys/class/power_supply/usb/online");
            f.add("hw: USB physically connected (sysfs online=%s)",
                  on.empty() ? "1" : on.c_str());
            /* 插着线本身不算风险(可能只是充电),但如果同时 ADC 开着就是风险 */
        } else if (usb == 0) {
            f.add("hw: no USB cable attached (sysfs)");
        }
        /* Java 的 UsbManager 判断优先(有些机型 sysfs 节点不同) */
        if (util::env_has(SEC_FACT_USB_CONNECTED)) {
            int j = util::env_facts().usb_connected;
            f.add("java: UsbManager usb_connected=%d", j);
            if (j == 1) usb = 1;
        }

        /* ---------- 2) USB 调试开关(Java 回填) ---------- */
        bool adb_on = false;
        if (util::env_has(SEC_FACT_ADB_ENABLED)) {
            int a = util::env_facts().adb_enabled;
            if (a == 1) {
                f.add("java: Settings.Global.ADB_ENABLED=1 (USB 调试已打开)");
                risk = true;
                adb_on = true;
            } else {
                f.add("java: Settings.Global.ADB_ENABLED=0");
            }
        }
        if (util::env_has(SEC_FACT_DEV_OPTIONS) && util::env_facts().dev_options == 1) {
            f.add("java: DEVELOPMENT_SETTINGS_ENABLED=1 (开发者选项已打开)");
            risk = true;
        }
        if (util::env_has(SEC_FACT_MOCK_LOCATION) && util::env_facts().mock_location == 1) {
            f.add("java: 允许模拟位置(定位造假)");
            risk = true;
        }

        /* ---------- 3) native 侧:属性/端口 ---------- */
        auto config_has_adb = [&](const char* prop) {
            std::string cfg = util::get_prop(prop);
            if (cfg.find("adb") != std::string::npos) {
                f.add("usb: %s=%s (adb enabled)", prop, cfg.c_str());
                risk = true;
                adb_on = true;
            }
        };
        config_has_adb("persist.sys.usb.config");
        config_has_adb("sys.usb.config");

        std::string dbg = util::get_prop("ro.debuggable");
        if (dbg == "1") {
            f.add("rom: ro.debuggable=1 (eng/userdebug 固件,adbd 默认 root)");
            risk = true;
        }
        if (util::get_prop("ro.secure") == "0") {
            f.add("rom: ro.secure=0 (adbd 以 root 运行)");
            risk = true;
        }

        /* 网络 adb(tcpip 模式):端口来自属性或固定 5555 */
        std::string tp = util::get_prop("service.adb.tcp.port");
        if (tp.empty()) tp = util::get_prop("persist.adb.tcp.port");
        if (!tp.empty()) {
            f.add("adb: network adb enabled (port prop=%s)", tp.c_str());
            risk = true;
        }
        std::vector<util::ListenPort> ports;
        util::list_listening_ports(ports);
        for (const auto& lp : ports) {
            if (lp.port == 5555 || lp.port == 5554) {
                f.add("adb: listening :%u (network adb, owner=%s)", lp.port,
                      lp.owner.empty() ? "?" : lp.owner.c_str());
                risk = true;
            }
        }

        /* 4) 如果 Java 没回填,提示怎么补(而不是猜) */
        if (!util::env_has(SEC_FACT_ADB_ENABLED)) {
            f.add("info: ADB_ENABLED not provided by Java; "
                  "native alone cannot read Settings.Global (see SecDetectBridge.java)");
            /* 退一步:试着用 settings 命令(部分环境无权限,失败就忽略) */
            std::string s = util::first_line_of("settings get global adb_enabled 2>/dev/null");
            if (s == "1" || s == "0") {
                f.add("fallback: settings get global adb_enabled=%s", s.c_str());
                if (s == "1") risk = true;
            }
        }

        if (usb == 1 && adb_on)
            f.add("combined: 数据线已连接 + USB 调试开启 = 完整 adb 调试通道");
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_usb_detector() {
    return new sec::UsbDebugDetector();
}
