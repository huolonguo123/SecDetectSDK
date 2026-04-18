/*
 * internal.h — 检测器内部公共头(不进 SDK 导出面)
 *
 * 结构:
 *   Findings    —— 证据收集器(子类往里 add 文本,基类收尾拼 output)
 *   BaseDetector—— 抽象基类:每个检测项一个子类,实现 run() 填证据
 *   util::xxx   —— 无依赖的小工具(读 /proc、属性、端口、文件、SHA-256)
 */
#ifndef SECDETECT_INTERNAL_H
#define SECDETECT_INTERNAL_H

#include "sec_detect_api.h"   // 枚举 / 返回码 / SEC_API 宏

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace sec {

/* ================= Findings:证据收集器 =================
 * 固定 1023 字节内部缓冲:证据串再长也没意义,截断即可。
 * add() 内部自带 '; ' 分隔与截断保护,子类无脑调。         */
class Findings {
public:
    Findings() : len_(0) { buf_[0] = '\0'; }

    void add(const char* fmt, ...) __attribute__((format(printf, 2, 3))) {
        if (len_ >= kCap - 1) return;          // 已满,丢弃(证据够多了)
        if (len_ > 0 && len_ < kCap - 2) {     // 非首条,先补分隔符
            buf_[len_++] = ';';
            buf_[len_++] = ' ';
        }
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(buf_ + len_, kCap - len_, fmt, ap);
        va_end(ap);
        if (n > 0) {
            size_t w = (size_t)n;
            if (len_ + w >= kCap) {            // 这条写不下:截断 + 尾巴标记
                len_ = kCap - 2;
                buf_[len_] = '~';
                buf_[len_ + 1] = '\0';
            } else {
                len_ += w;
            }
        }
    }

    const char* c_str() const { return buf_; }
    bool empty() const { return len_ == 0; }

private:
    static const size_t kCap = 1024;
    char buf_[kCap];
    size_t len_;
};

/* ================= BaseDetector:抽象基类 =================
 * 子类职责:在 run() 里做检测,命中就把证据 add 进 f。
 * 基类职责(api 层调用):统一收尾——run 返回 true 则把证据拷进
 * output 并返回 SEC_RISK;false 则返回 SEC_OK(证据可为空)。
 * 这样"检测逻辑"与"返回码/截断/缓冲管理"彻底分离。          */
class BaseDetector {
public:
    virtual ~BaseDetector() = default;

    /* 检测项对外名字(诊断/日志用) */
    virtual const char* name() const = 0;
    /* 枚举号(与 sec_detect_api.h 一致) */
    virtual int type() const = 0;
    /* 是否需要 input(目前只有 repack 要) */
    virtual bool needs_input() const { return false; }

    /* 核心虚函数:执行检测,input 可空;命中→true 并填 f。
     * 约定:false 也可能往 f 写内容(如 repack 校准模式输出指纹)。 */
    virtual bool run(const char* input, Findings& f) = 0;
};

/* ================= 工具层(util.cpp 实现) ================= */
namespace util {

/* -- 文件 -- */
bool file_exists(const char* path);         // 是普通文件
bool path_exists(const char* path);         // 任意类型(文件/目录/socket)F_OK
bool file_executable(const char* path);     // X_OK
bool read_small_file(const char* path, std::string& out);       // 文本
bool read_small_file(const char* path, std::vector<uint8_t>& out); // 二进制
/* 列目录(失败返回空);名字原样进 out,供调用方自己匹配 */
void list_dir(const char* path, std::vector<std::string>& out);

/* -- /proc/<pid>/... 目标进程取证(pid<=0 = 自己) -- */
/* 解析 input:"pid:1234" -> 1234;NULL/其它 -> 0(自己) */
int target_pid(const char* input);
int tracer_pid_of(int pid);                 // TracerPid 字段,0=没被附加
std::string exe_of(int pid);                // readlink /proc/<pid>/exe
std::string maps_of(int pid);               // maps 全文(读失败空串)
bool maps_path_contains(int pid, const char* keyword); // 任一映射路径含 keyword

/* -- /proc/net/tcp(含 tcp6):指定本地端口是否在 LISTEN -- */
bool tcp_port_listening(uint16_t port);

/* -- /proc/<pid>/cmdline 遍历:进程名含 keyword? -- */
bool any_process_cmdline_contains(const char* keyword);

/* -- Android 系统属性(封装 __system_property_get) -- */
std::string get_prop(const char* name);

/* -- popen 跑一条命令拿第一行输出(找不到命令返回空) -- */
std::string first_line_of(const char* cmd);

/* -- SHA-256(纯 C 实现,零依赖;返回 64 位小写 hex) -- */
std::string sha256_hex(const uint8_t* data, size_t len);
std::string sha256_file_hex(const char* path);  // 失败返回空串

/* -- 简易 ZIP 定位:取 APK 中第一个 META-INF 目录下的 v1 签名文件
 *    (.RSA/.DSA/.EC;stored 直读,deflate 则 inflate;需 HAVE_ZLIB)。
 *    返回 false = 打开失败或找不到签名块。 -- */
bool apk_first_signature(const char* apk_path, std::vector<uint8_t>& out);

/* -- base16 解析:hex 字符串 -> 字节(失败返回 false) -- */
bool hex_decode(const char* hex, std::vector<uint8_t>& out);

}  // namespace util

/* ================= 子类工厂(各 det_*.cpp 实现,api.cpp 汇总) =================
 * extern "C" 是为了让符号名稳定、方便调试器辨认;返回堆对象,api 层管理。 */
}  // namespace sec

extern "C" {
sec::BaseDetector* sec_make_root_detector();
sec::BaseDetector* sec_make_debugger_detector();
sec::BaseDetector* sec_make_frida_detector();
sec::BaseDetector* sec_make_xposed_detector();
sec::BaseDetector* sec_make_emulator_detector();
sec::BaseDetector* sec_make_vm_detector();
sec::BaseDetector* sec_make_repack_detector();
sec::BaseDetector* sec_make_bootloader_detector();
sec::BaseDetector* sec_make_usb_detector();
sec::BaseDetector* sec_make_module_detector();
}

#endif /* SECDETECT_INTERNAL_H */
