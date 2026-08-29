/*
 * det_emulator.cpp — 检测项 5:模拟器(QEMU / PC 模拟器 / 云手机)
 *
 * 模拟器检测本质是"找不存在的硬件 / 找虚拟化留下的结构",也是
 * 反作弊里最常见的一个对抗面(腾讯系模拟器检测被绕过的方式,
 * 就是逐个把下面这些点擦掉;反过来,我们把这些点全查一遍)。
 *
 * 检查项来源:业界公开的 anti-emulator 特征集(文件特征 + 属性
 * 特征 + /dev 节点 + /proc 内核视图 + GPU/传感器),并按 PC 模拟器
 * (MuMu / 雷电 / 夜神 / 逍遥 / BlueStacks / Genymotion / AVD /
 *  腾讯手游助手)的实际落地形态补全。
 *
 * 五大类证据:
 *   1) ro.* 属性:qemu/goldfish/ranchu/sdk/厂商名/指纹
 *   2) ★ ARM→x86 转译层:ro.dalvik.vm.native.bridge = libhoudini.so /
 *      libndk_translation.so,或 /system/lib/libhoudini.so 存在
 *      —— PC 上跑 ARM 手游必装这个,**这是"这不是手机"的最强判据**
 *      (真机 arm64 上是空的)
 *   3) /dev 与系统文件:goldfish_pipe/qemu_pipe/qemud/厂商私有 so
 *   4) /proc 内核视图:cmdline(qemu/ranchu)、tty/drivers(goldfish)、
 *      cpuinfo(Hardware: goldfish/ranchu,x86 vendor_id)
 *   5) Java 回填:传感器数量 == 0、GL_RENDERER 含 SwiftShader/Emulator
 *      (模拟器的 GPU 走软件渲染,GL_RENDERER 会直接写出来)
 *
 * 局限:改 prop(resetprop)能藏住第 1 类;/dev 节点与系统镜像文件
 * 要一起改就得重打包镜像,成本高(第 3 类因此更可信);第 5 类
 * 依赖宿主把渲染器/传感器也伪造了,PC 模拟器很难全伪造。
 */
#include "internal.h"

namespace sec {

namespace {

/* (属性名, 关键词) —— 属性值含关键词即命中 */
struct PropNeedle { const char* prop; const char* needle; };
const PropNeedle kPropNeedles[] = {
    {"ro.hardware",              "goldfish"},
    {"ro.hardware",              "ranchu"},
    {"ro.boot.hardware",         "goldfish"},
    {"ro.boot.hardware",         "ranchu"},
    {"ro.hardware.chipname",     "goldfish"},
    {"ro.hardware.chipname",     "ranchu"},
    {"ro.product.device",        "goldfish"},
    {"ro.product.device",        "ranchu"},
    {"ro.product.board",         "goldfish"},
    {"ro.product.board",         "ranchu"},
    {"ro.product.model",         "sdk"},
    {"ro.product.model",         "emulator"},
    {"ro.product.model",         "google_sdk"},
    {"ro.product.model",         "android sdk"},
    {"ro.product.manufacturer",  "genymotion"},
    {"ro.product.manufacturer",  "unknown"},
    {"ro.product.brand",         "generic"},
    {"ro.product.brand",         "vbox"},
    {"ro.product.brand",         "ttvm"},
    {"ro.product.brand",         "nox"},
    {"ro.product.brand",         "bluestacks"},
    {"ro.product.brand",         "microvirt"},
    {"ro.product.brand",         "mumu"},
    {"ro.product.brand",         "ldplayer"},
    {"ro.product.brand",         "nemu"},
    {"ro.build.fingerprint",     "generic"},
    {"ro.build.fingerprint",     "vbox"},
    {"ro.build.fingerprint",     "ttvm"},
    {"ro.build.fingerprint",     "genymotion"},
    {"ro.build.fingerprint",     "bluestacks"},
    {"ro.build.product",         "generic"},
    {"ro.build.product",         "sdk"},
    {"ro.build.host",            "vbox"},
    {"ro.serialno",              "unknown"},
    {"ro.boot.serialno",         "unknown"},
    {"ro.boot.serialno",         "0123456789ABCDEF"},
    {"ro.boot.serialno",         "emulator"},
    {"ro.boot.qemu.avd_name",    "avd"},          /* AVD 名(非空即命中) */
};

/* 单值判定:非空 / 等于特定值 */
struct PropExact { const char* prop; const char* value; const char* what; };
const PropExact kPropExact[] = {
    {"ro.kernel.qemu", "1", "内核启动参数直说在 qemu 上"},
    {"ro.boot.qemu",   "1", "bootloader 标记 qemu"},
    {"qemu.hw.mainkeys", "1", "qemu 硬件按键配置"},
};

/* 系统文件 / 设备节点 / 厂商私有库 */
struct FileNeedle { const char* path; const char* what; };
const FileNeedle kFiles[] = {
    /* QEMU/AVD 通用 */
    {"/dev/socket/qemud",                      "qemud socket(guest↔host 通信)"},
    {"/dev/qemu_pipe",                         "qemu pipe 虚拟设备"},
    {"/dev/goldfish_pipe",                     "goldfish pipe 虚拟设备"},
    {"/dev/goldfish",                          "goldfish 虚拟设备"},
    {"/dev/qemu_trace",                        "qemu trace 设备"},
    {"/dev/socket/genyd",                      "Genymotion socket"},
    {"/dev/socket/baseband_genyd",             "Genymotion baseband"},
    {"/dev/socket/baseband_genyd0",            "Genymotion baseband"},
    {"/system/bin/qemud",                      "qemud 二进制"},
    {"/system/bin/qemu-props",                 "qemu-props 二进制"},
    {"/system/lib/libc_malloc_debug_qemu.so",  "qemu malloc debug"},
    {"/system/lib64/libc_malloc_debug_qemu.so","qemu malloc debug"},
    {"/init.goldfish.rc",                      "goldfish init 脚本"},
    {"/system/etc/init.goldfish.sh",           "goldfish init 脚本"},
    {"/sys/qemu_trace",                        "qemu trace sysfs"},
    /* ★ ARM 转译层(PC 模拟器跑 ARM 应用必装) */
    {"/system/lib/libhoudini.so",              "Intel houdini ARM 转译层"},
    {"/system/lib64/libhoudini.so",            "Intel houdini ARM 转译层"},
    {"/system/lib/libndk_translation.so",      "Google ndk_translation ARM 转译层"},
    {"/system/lib64/libndk_translation.so",    "Google ndk_translation ARM 转译层"},
    {"/system/bin/houdini",                    "houdini 可执行"},
    {"/system/bin/ndk_translation",            "ndk translation 可执行"},
    {"/system/lib/libarm.so",                  "libarm 转译层"},
    /* 厂商私有(PC 模拟器) */
    {"/system/bin/nox",                        "夜神 Nox"},
    {"/system/bin/nox-vbox-sf",                "夜神 Nox"},
    {"/system/bin/noxd",                       "夜神 Nox"},
    {"/system/lib/libnoxd.so",                 "夜神 Nox"},
    {"/system/bin/nemud",                      "NEMU"},
    {"/system/bin/droid4x",                    "Droid4X"},
    {"/system/lib/libdroid4x.so",              "Droid4X"},
    {"/system/bin/microvirtd",                 "逍遥模拟器 microvirt"},
    {"/system/lib/libmicrovirt.so",            "逍遥模拟器 microvirt"},
    {"/system/bin/ldinit",                     "雷电模拟器"},
    {"/system/lib/libldplayer.so",             "雷电模拟器"},
    {"/system/bin/bstk",                       "BlueStacks"},
    {"/system/lib/libbstk.so",                 "BlueStacks"},
    {"/system/bin/andy",                       "Andy 模拟器"},
    {"/system/bin/mumu",                       "MuMu 模拟器"},
    {"/system/lib/libmumu.so",                 "MuMu 模拟器"},
    {"/system/bin/genymotion",                 "Genymotion"},
    {"/system/lib/libgenyd.so",                "Genymotion"},
    /* 软件渲染 / 云手机 */
    {"/system/lib/libGLES_emulation.so",       "软件 GLES 模拟"},
    {"/system/lib64/libGLES_emulation.so",     "软件 GLES 模拟"},
    {"/system/lib64/libvk_swiftshader.so",     "SwiftShader 软件渲染"},
    {"/system/lib/libvk_swiftshader.so",       "SwiftShader 软件渲染"},
    {"/dev/vsoc",                              "Cuttlefish/云手机 vsoc 设备"},
    /* ★ /dev/kvm 故意不放进这张表:原生机型(Android 13+ Pixel)由 pKVM/AVF 提供该节点,
     *   一律判风险会误报 —— 见下面 3b) 的 AVF 判定。 */
};

/* 属性名列表(存在即算命中,不看值) */
const char* kPropPresence[] = {
    "ro.boot.qemu.avd_name",   /* AVD 名 */
    "ro.boot.qemu.gltransport", /* qemu 传输方式 */
    "ro.boot.qemu.virtiowifi",
    "ro.kernel.qemu.gles",
    "qemu.sf.lcd_density",     /* qemu 专用密度属性 */
};

const char* kNativeBridgeUnset[] = {"", "0", "false"};

}  // namespace

class EmulatorDetector : public BaseDetector {
public:
    const char* name() const override { return "emulator"; }
    int type() const override { return DETECT_EMULATOR; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);
        const char* who = (pid > 0) ? "emulator[pid]:" : "emulator:";

        /* ---------- 1) 属性关键词 ---------- */
        for (const PropNeedle& pn : kPropNeedles) {
            std::string v = util::get_prop(pn.prop);
            if (v.empty()) continue;
            std::string low = v;
            for (auto& c : low) c = (char)tolower((unsigned char)c);
            if (low.find(pn.needle) != std::string::npos) {
                f.add("prop: %s=%s (~'%s')", pn.prop, v.c_str(), pn.needle);
                risk = true;
            }
        }
        for (const PropExact& pe : kPropExact) {
            std::string v = util::get_prop(pe.prop);
            if (v == pe.value) {
                f.add("prop: %s=%s (%s)", pe.prop, v.c_str(), pe.what);
                risk = true;
            }
        }
        for (const char* n : kPropPresence) {
            std::string v = util::get_prop(n);
            if (!v.empty()) {
                f.add("prop: %s=%s present", n, v.c_str());
                risk = true;
            }
        }

        /* ---------- 2) ★ ARM 转译层(PC 模拟器最强判据) ---------- */
        std::string br = util::get_prop("ro.dalvik.vm.native.bridge");
        bool bridge_unset = false;
        for (const char* s : kNativeBridgeUnset)
            if (br == s) bridge_unset = true;
        if (!bridge_unset) {
            f.add("prop: ro.dalvik.vm.native.bridge=%s "
                  "(ARM 应用跑在 x86 上 → PC 模拟器)", br.c_str());
            risk = true;
        }
        std::string abi = util::get_prop("ro.product.cpu.abi");
        if (abi.rfind("x86", 0) == 0) {
            f.add("prop: ro.product.cpu.abi=%s (Android 真机是 arm)", abi.c_str());
            risk = true;
        }
        std::string abilist = util::get_prop("ro.product.cpu.abilist");
        if (abilist.find("x86") != std::string::npos && abilist.find("arm") != std::string::npos) {
            f.add("prop: abilist=%s (x86+arm 混合 = 带转译层的模拟器)", abilist.c_str());
            risk = true;
        }
        for (const FileNeedle& fn : kFiles)
            if (fn.path[0] && util::path_exists(fn.path) &&
                (strstr(fn.what, "转译") || strstr(fn.what, "houdini"))) {
                f.add("file: %s (%s)", fn.path, fn.what);
                risk = true;
            }

        /* ---------- 3) /dev 与系统文件(非转译类) ---------- */
        for (const FileNeedle& fn : kFiles) {
            if (!fn.path[0]) continue;
            if (strstr(fn.what, "转译") || strstr(fn.what, "houdini")) continue;
            if (util::path_exists(fn.path)) {
                f.add("file: %s (%s)", fn.path, fn.what);
                risk = true;
            }
        }

        /* ---------- 3b) /dev/kvm:先看有没有 AVF(Android Virtualization Framework)----------
         * 实测(2026-09,Pixel 7 / Android 13):/dev/kvm 是 crw------- system:system 的**系统设备节点**,
         * 且 /apex/com.android.virt@1 存在 —— pKVM/AVF 是原生机型的标准组件,不是模拟器特征。
         * 只有**没有 AVF** 的宿主(模拟器宿主 / 云手机)才把 /dev/kvm 当命中。 */
        if (util::path_exists("/dev/kvm")) {
            if (util::path_exists("/apex/com.android.virt") ||
                util::path_exists("/apex/com.android.virt@1")) {
                f.add("info: /dev/kvm 存在,但同时有 /apex/com.android.virt(AVF/pKVM)→ 原生组件,不算模拟器");
            } else {
                f.add("file: /dev/kvm (KVM 虚拟化且无 AVF → 模拟器/云手机宿主特征)");
                risk = true;
            }
        }

        /* ---------- 4) /proc 内核视图 ---------- */
        std::string cmdline;
        if (util::read_small_file("/proc/cmdline", cmdline)) {
            static const char* kCmd[] = {"qemu", "goldfish", "ranchu"};
            for (const char* k : kCmd)
                if (cmdline.find(k) != std::string::npos) {
                    f.add("cmdline: %s", cmdline.c_str());
                    risk = true;
                    break;
                }
        }
        std::string tty;
        if (util::read_small_file("/proc/tty/drivers", tty) &&
            tty.find("goldfish") != std::string::npos) {
            f.add("tty: /proc/tty/drivers contains goldfish");
            risk = true;
        }
        std::string cpuinfo;
        if (util::read_small_file("/proc/cpuinfo", cpuinfo)) {
            static const char* kCpu[] = {"goldfish", "ranchu", "QEMU", "Virtual CPU"};
            for (const char* k : kCpu)
                if (cpuinfo.find(k) != std::string::npos) {
                    f.add("cpuinfo: contains '%s'", k);
                    risk = true;
                    break;
                }
        }

        /* ---------- 5) 目标进程里的转译层 / 模拟器库映射 ---------- */
        static const char* kMapKw[] = {"houdini", "ndk_translation", "libarm.so",
                                       "nox", "microvirt", "ldplayer", "bluestacks",
                                       "swiftshader"};
        for (const char* k : kMapKw)
            if (util::maps_path_contains(pid, k)) {
                f.add("%s maps: '%s'", who, k);
                risk = true;
            }

        /* ---------- 6) Java 回填:传感器 / GL 渲染器 ---------- */
        if (util::env_has(SEC_FACT_SENSOR_COUNT)) {
            int n = util::env_facts().sensor_count;
            if (n == 0) {
                f.add("java: SensorManager 传感器数量=0 (真机不可能)");
                risk = true;
            }
        }
        if (util::env_has(SEC_FACT_GL_RENDERER)) {
            std::string gl = util::env_facts().gl_renderer;
            std::string low = gl;
            for (auto& c : low) c = (char)tolower((unsigned char)c);
            static const char* kGl[] = {"swiftshader", "emulator", "llvmpipe",
                                        "mesa", "bluestacks", "angle", "virgl"};
            for (const char* k : kGl)
                if (low.find(k) != std::string::npos) {
                    f.add("java: GL_RENDERER=%s (软件渲染/模拟器 GPU)", gl.c_str());
                    risk = true;
                    break;
                }
        }
        if (util::env_has(SEC_FACT_BLUETOOTH) && util::env_facts().bluetooth == 0)
            f.add("java: 无蓝牙适配器(模拟器常见)");

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_emulator_detector() {
    return new sec::EmulatorDetector();
}
