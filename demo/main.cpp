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
};

int parse_type(const char* s) {
    if (strcmp(s, "all") == 0) return DETECT_ALL;
    for (const Item& it : kItems)
        if (strcmp(s, it.name) == 0) return it.type;
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if (end && *end == '\0' && v >= 1 && v <= 10) return (int)v;
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
    printf("  secdetect all [apk_path]        run all 9 checks "
           "(pass apk to include repack)\n");
    printf("  secdetect <name|1..9> [input]   run one check\n");
    printf("  secdetect loop                  watch frida/debugger every 2s "
           "(attach with frida to demo)\n");
    printf("  secdetect tee                   show TEE backend status\n");
    printf("checks: ");
    for (const Item& it : kItems) printf("%s(%d) ", it.name, it.type);
    printf("\nrepack input: <apk_path>[,<baseline_sha256>]  "
           "(no baseline = calibration, prints fingerprint)\n");
}

}  // namespace

int main(int argc, char** argv) {
    char out[2048];
    /* adb shell 下 stdout 是块缓冲,先切成行缓冲,保证打印实时可见 */
    setvbuf(stdout, nullptr, _IOLBF, 0);

    if (argc < 2) { usage(); return 0; }

    printf("=== SecDetect SDK v%s ===  pid=%d euid=%d\n",
           SECDETECT_VERSION, (int)getpid(), (int)geteuid());

    /* loop 模式:周期自检注入类风险,配合 frida -p attach 演示 */
    if (strcmp(argv[1], "loop") == 0) {
        printf("loop: watching FRIDA/DEBUGGER every 2s; my pid=%d\n", (int)getpid());
        printf("now attach me from host:  frida -H 127.0.0.1:39001 -p %d\n", (int)getpid());
        for (;;) {
            char o1[512] = {0}, o2[512] = {0};
            int r1 = secdetect(DETECT_FRIDA, nullptr, o1, sizeof o1);
            int r2 = secdetect(DETECT_DEBUGGER, nullptr, o2, sizeof o2);
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
