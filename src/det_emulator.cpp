/*
 * det_emulator.cpp — 检测项 5:QEMU 类模拟器
 *
 * 原理:Android 模拟器(官方 AVD、Genymotion、MuMu/夜神等)
 * 底层都是 QEMU。QEMU 要为 guest 提供"虚拟外设",必然在系统里
 * 留下大量无法抹干净的痕迹:
 *
 *   - ro.kernel.qemu=1:内核启动参数直说"我在 qemu 上";
 *   - goldfish/ranchu 是 AVD 的虚拟硬件平台名,会出现在
 *     ro.hardware / ro.product.device 与 /dev 节点名里;
 *   - /dev/goldfish_pipe、/dev/qemu_pipe 是 guest 与宿主通信的
 *     虚拟设备——真机物理上不可能有。
 *
 * 模拟器检测本质是"找不存在的硬件"。改 prop 能藏住属性,
 * 但 /dev 节点、qemud 二进制这些属于系统镜像内容,要一起改
 * 就得重打包镜像——检测成本被抬高了。
 */
#include "internal.h"

namespace sec {

class EmulatorDetector : public BaseDetector {
public:
    const char* name() const override { return "emulator"; }
    int type() const override { return DETECT_EMULATOR; }

    bool run(const char*, Findings& f) override {
        bool risk = false;

        /* 1) 内核直说 */
        std::string qemu = util::get_prop("ro.kernel.qemu");
        if (qemu == "1") {
            f.add("prop: ro.kernel.qemu=1");
            risk = true;
        }
        std::string bootqemu = util::get_prop("ro.boot.qemu");
        if (!bootqemu.empty()) {
            f.add("prop: ro.boot.qemu=%s", bootqemu.c_str());
            risk = true;
        }

        /* 2) 虚拟硬件平台名 */
        auto prop_contains = [&](const char* name, const char* needle) {
            std::string v = util::get_prop(name);
            if (v.find(needle) != std::string::npos) {
                f.add("prop: %s=%s", name, v.c_str());
                risk = true;
            }
        };
        prop_contains("ro.hardware", "goldfish");
        prop_contains("ro.hardware", "ranchu");
        prop_contains("ro.product.device", "goldfish");
        prop_contains("ro.product.device", "ranchu");
        prop_contains("ro.product.model", "sdk");
        prop_contains("ro.product.model", "google_sdk");
        prop_contains("ro.product.model", "Emulator");
        prop_contains("ro.build.fingerprint", "generic");

        /* 3) 虚拟设备节点(真机不可能存在) */
        static const char* devs[] = {
            "/dev/goldfish_pipe", "/dev/qemu_pipe",
            "/dev/goldfish", "/dev/qemu_trace",
        };
        for (const char* d : devs) {
            if (util::path_exists(d)) {
                f.add("dev: %s", d);
                risk = true;
            }
        }

        /* 4) QEMU 配套二进制 */
        static const char* bins[] = {
            "/system/bin/qemud", "/system/bin/qemu-props",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/lib64/libc_malloc_debug_qemu.so",
        };
        for (const char* b : bins) {
            if (util::file_exists(b)) {
                f.add("sys: %s", b);
                risk = true;
            }
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_emulator_detector() {
    return new sec::EmulatorDetector();
}
