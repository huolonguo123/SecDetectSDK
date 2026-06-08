/*
 * main.cpp — SecDetect 命令行 runner(实机验证用)
 *
 * 用法(在 Android 设备上):
 *   ./secdetect                    # 打印用法
 *   ./secdetect all                # 9 项全扫
 *   ./secdetect all /sdcard/x.apk  # 全扫 + 带上 APK 让 repack 参与
 *   ./secdetect root               # 按名字单测
 *   ./secdetect 7 /sdcard/x.apk             # repack 校准(打印当前指纹)
 *   ./secdetect 7 /sdcard/x.apk,<sha256>   # repack 比对
 *   ./secdetect tee                # 看 TEE 后端占位状态
 *
 * 本文件只做"翻译参数 + 打印",检测全部走 libsecsdk 的 C ABI,
 * 与真实 App 集成路径(Java -> JNI -> secdetect())完全一致。
 *
 * loop 模式(验证注入检测用):
 *   secdetect loop
 * 每 2 秒自检一次 FRIDA/DEBUGGER 并打印——跑起来后另开终端用
 *   frida -H 127.0.0.1:39001 -p <secdetect 的 pid>
 * 注入它,下一轮循环它查自己 /proc/self/maps 就会报 frida=1,
 * 这就是"检测器跑在被注入进程内部"的真实工作形态。
 */
#include "sec_detect_api.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <unistd.h>

namespace {

struct Item {
    int type;
    const char* name;
};

const Item kItems[] = {
    {DETECT_ROOT, "root"},         {DETECT_DEBUGGER, "debugger"},
    {DETECT_FRIDA, "frida"},       {DETECT_XPOSED, "xposed"},
    {DETECT_EMULATOR, "emulator"}, {DETECT_VM, "vm"},
    {DETECT_REPACK, "repack"},     {DETECT_BOOTLOADER, "bootloader"},
    {DETECT_USB_DEBUG, "usb_debug"}, {DETECT_MODULE, "module"},
    {DETECT_INTEGRITY, "integrity"}, {DETECT_IDA, "ida"},
};

int parse_type(const char* s) {
    if (strcmp(s, "all") == 0) return DETECT_ALL;
    for (const Item& it : kItems)
        if (strcmp(s, it.name) == 0) return it.type;
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if (end && *end == '\0' && v >= 1 && v <= 12) return (int)v;
    return -1;
}

const char* verdict_str(int r) {
    switch (r) {
        case SEC_OK:       return "OK    (0, no risk found)";
        case SEC_RISK:     return "RISK  (1, risk detected)";
        case SEC_ERR_PARAM:return "PARAM (-1, bad argument)";
        default:           return "????";
    }
}

void usage() {
    printf("SecDetect SDK v%s — command-line runner\n", SECDETECT_VERSION);
    printf("usage:\n");
    printf("  secdetect all [apk_path]        run all 12 checks "
           "(pass apk to include repack)\n");
    printf("  secdetect <name|1..12> [input]  run one check\n");
    printf("  secdetect loop [pid:N]          watch frida/debugger every 2s "
           "(attach to self, or target pid:N)\n");
    printf("  secdetect env                   show Java/env facts currently set\n");
    printf("  secdetect repack-auto <apk>[,<base>]  repack with input=NULL "
           "(simulates App integration: path/baseline come from env facts)\n");
    printf("  secdetect tee                   show TEE backend status\n");
    printf("checks: ");
    for (const Item& it : kItems) printf("%s(%d) ", it.name, it.type);
    printf("\nrepack input (optional): <apk_path>[,<md5|sha256>[|<more digests>]]  "
           "(no baseline = calibration; omit entirely if Java fills SEC_FACT_APK_PATH)\n");
    printf("multi-split apk: join paths with '|'  e.g. \"/data/app/x/base.apk|/data/app/x/split_config.arm64_v8a.apk\"\n");
    printf("scan-other-process input for root/debugger/frida/xposed/vm/module/"
           "integrity/ida/usb_debug/emulator: pid:<pid>  (needs root; empty = self)\n");
    printf("env facts are filled by Java/JNI: secdetect_set_env_facts() — see "
           "java/ and jni/\n");
}

}  // namespace

int main(int argc, char** argv) {
    char out[64 * 1024];   /* all 的单项证据可到 ~1.7KB;2048 会把后面的项整段截掉(真机实测) */
    /* adb shell 下 stdout 是块缓冲,先切成行缓冲,保证打印实时可见 */
    setvbuf(stdout, nullptr, _IOLBF, 0);

    if (argc < 2) { usage(); return 0; }

    printf("=== SecDetect SDK v%s ===  pid=%d euid=%d\n",
           SECDETECT_VERSION, (int)getpid(), (int)geteuid());

    /* loop 模式:周期自检注入类风险,配合 frida -p attach 演示;
     * 可选参数 pid:<N> 让检测指向别的进程(需 root) */
    if (strcmp(argv[1], "loop") == 0) {
        const char* target = (argc >= 3) ? argv[2] : nullptr;
        int tpid = 0;
        if (target && strncmp(target, "pid:", 4) == 0) tpid = atoi(target + 4);
        printf("loop: watching FRIDA/DEBUGGER every 2s; target=%s\n",
               (tpid > 0) ? target : "self");
        if (tpid > 0) {
            printf("attach to that process from host:  "
                   "frida -H 127.0.0.1:39001 -p %d\n", tpid);
        } else {
            printf("now attach me from host:  frida -H 127.0.0.1:39001 -p %d\n",
                   (int)getpid());
        }
        for (;;) {
            char o1[512] = {0}, o2[512] = {0};
            int r1 = secdetect(DETECT_FRIDA, target, o1, sizeof o1);
            int r2 = secdetect(DETECT_DEBUGGER, target, o2, sizeof o2);
            printf("t=%ld  frida=%d [%s]  debugger=%d [%s]\n",
                   (long)time(nullptr), r1, o1[0] ? o1 : "clean",
                   r2, o2[0] ? o2 : "clean");
            sleep(2);
        }
    }

    /* TEE 占位状态 */
    if (strcmp(argv[1], "tee") == 0) {
        out[0] = '\0';
        int r = secdetect_tee_attest(out, sizeof out);
        printf("tee_attest -> %d\n%s\n", r, out);
        return 0;
    }

    /* 环境事实(Java/JNI 回填了什么,一目了然) */
    if (strcmp(argv[1], "env") == 0) {
        sec_env_facts_t ef;
        secdetect_get_env_facts(&ef);
        printf("env facts provided mask = 0x%x\n", ef.provided);
        printf("  usb_connected=%d adb_enabled=%d dev_options=%d mock_location=%d\n",
               ef.usb_connected, ef.adb_enabled, ef.dev_options, ef.mock_location);
        printf("  pkg_count_for_uid=%d sensor_count=%d bluetooth=%d hw_backed_key=%d\n",
               ef.pkg_count_for_uid, ef.sensor_count, ef.bluetooth, ef.hw_backed_key);
        printf("  gl_renderer=\"%s\"\n", ef.gl_renderer);
        printf("  apk_path=\"%s\"\n", ef.apk_path);
        printf("  apk_baseline=\"%s\"\n", ef.apk_baseline);
        printf("  attest: verified_boot_state=%d device_locked=%d hash_ok=%d "
               "sw_enforced=%d level=\"%s\" os=\"%s\"\n",
               ef.att_verified_boot_state, ef.att_device_locked,
               ef.att_verified_boot_hash_ok, ef.att_sw_enforced,
               ef.att_security_level, ef.att_os_version);
        return 0;
    }

    /* 模拟"App 集成形态":把 APK 路径/基线放进 env facts,再以 input=NULL 跑 repack。
     * 用法: secdetect repack-auto <apk>[,<baseline>]
     * 用途:证明 App 里 repack 项不需要再传 apk 路径(路径由 Java 回填)。 */
    if (strcmp(argv[1], "repack-auto") == 0) {
        if (argc < 3) { printf("usage: secdetect repack-auto <apk>[,<baseline>]\n"); return 2; }
        sec_env_facts_t ef;
        secdetect_get_env_facts(&ef);
        std::string in(argv[2]);
        size_t comma = in.find(',');
        std::string apk = (comma == std::string::npos) ? in : in.substr(0, comma);
        std::string base = (comma == std::string::npos) ? "" : in.substr(comma + 1);
        snprintf(ef.apk_path, sizeof ef.apk_path, "%s", apk.c_str());
        ef.provided |= SEC_FACT_APK_PATH;
        if (!base.empty()) {
            snprintf(ef.apk_baseline, sizeof ef.apk_baseline, "%s", base.c_str());
            ef.provided |= SEC_FACT_APK_BASELINE;
        }
        secdetect_set_env_facts(&ef);
        out[0] = '\0';
        int r = secdetect(DETECT_REPACK, nullptr, out, sizeof out);   /* 注意 input = NULL */
        printf("secdetect(REPACK, input=NULL) -> %s\n", verdict_str(r));
        if (out[0]) printf("---- findings ----\n%s\n", out);
        return r == SEC_ERR_PARAM ? 2 : r;
    }

    int type = parse_type(argv[1]);
    if (type < 0) { usage(); return 0; }

    const char* input = (argc >= 3) ? argv[2] : nullptr;

    if (type == DETECT_ALL) {
        out[0] = '\0';
        int r = secdetect(DETECT_ALL, input, out, sizeof out);
        printf("secdetect(ALL) -> %s\n", verdict_str(r));
        if (out[0]) printf("---- findings ----\n%s\n", out);
        return r == SEC_ERR_PARAM ? 2 : r;
    }

    out[0] = '\0';
    int r = secdetect(type, input, out, sizeof out);
    for (const Item& it : kItems) {
        if (it.type == type) {
            printf("== %s (%d) ==\n", it.name, it.type);
            break;
        }
    }
    printf("  verdict: %s\n", verdict_str(r));
    if (out[0]) printf("  evidence: %s\n", out);
    return r == SEC_ERR_PARAM ? 2 : r;
}
