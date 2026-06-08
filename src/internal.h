/*
 * internal.h — 检测器内部公共头(不进 SDK 导出面)
 *
 * 结构:
 *   Findings    —— 证据收集器(子类往里 add 文本,基类收尾拼 output)
 *   BaseDetector—— 抽象基类:每个检测项一个子类,实现 run() 填证据
 *   util::xxx   —— 无依赖的小工具(读 /proc、属性、端口、文件、哈希、内存)
 */
#ifndef SECDETECT_INTERNAL_H
#define SECDETECT_INTERNAL_H

#include "sec_detect_api.h"   // 枚举 / 返回码 / SEC_API 宏 / env facts

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace sec {

/* ================= Findings:证据收集器 =================
 * 固定 2047 字节内部缓冲:证据串再长也没意义,截断即可。
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
    static const size_t kCap = 2048;   // 证据变多(模块/线程/差异列表),翻倍
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

    /* 核心虚函数:执行检测,input 可空;命中→true 并填 f。
     * 约定:false 也可能往 f 写内容(如 repack 校准模式输出指纹)。
     * input 的语义由各子类自己解释:"pid:<pid>" 扫别的进程;repack 当
     * apk 路径(可空,空则用 env facts 里 Java 回填的路径)。 */
    virtual bool run(const char* input, Findings& f) = 0;
};

/* ================= 工具层(util.cpp / apk_signature.cpp / env_facts.cpp) ============ */
namespace util {

/* -- 文件 -- */
bool file_exists(const char* path);         // 是普通文件
bool path_exists(const char* path);         // 任意类型(文件/目录/socket)F_OK
bool file_executable(const char* path);     // X_OK
bool read_small_file(const char* path, std::string& out);       // 文本
bool read_small_file(const char* path, std::vector<uint8_t>& out); // 二进制
/* 列目录(失败返回空);名字原样进 out,供调用方自己匹配 */
void list_dir(const char* path, std::vector<std::string>& out);
/* 读文件第一行(去 \r\n);sysfs 用,失败返回空 */
std::string read_line_file(const char* path);

/* -- /proc/<pid>/... 目标进程取证(pid<=0 = 自己) -- */
/* 解析 input:"pid:1234" -> 1234;NULL/其它 -> 0(自己) */
int target_pid(const char* input);
int tracer_pid_of(int pid);                 // TracerPid 字段,0=没被附加
std::string exe_of(int pid);                // readlink /proc/<pid>/exe
std::string maps_of(int pid);               // maps 全文(读失败空串)
std::string proc_read(int pid, const char* leaf);  // 任意 /proc/<pid>/<leaf>
bool process_exists(int pid);               // /proc/<pid> 是否存在(pid<=0 恒真)
bool maps_path_contains(int pid, const char* keyword); // 任一映射路径含 keyword

/* -- maps 解析成结构化区域(比字符串匹配更精确) -- */
struct MapRegion {
    uint64_t start = 0, end = 0, off = 0;
    char perms[5] = {0};        // "r-xp" 之类
    std::string path;           // 已去掉 " (deleted)" 尾巴;匿名映射为空
    bool deleted = false;       // 路径带 " (deleted)"(临时文件 mmap 后 unlink)
    bool is_exec() const { return perms[2] == 'x'; }
    bool is_read() const { return perms[0] == 'r'; }
    bool is_write() const { return perms[1] == 'w'; }
    bool anonymous() const { return path.empty() || path[0] == '['; }
};
bool parse_maps(int pid, std::vector<MapRegion>& out);

/* -- 读目标进程内存(需 root 或同 uid;/proc/<pid>/mem) -- */
bool read_proc_mem(int pid, uint64_t addr, void* buf, size_t len);

/* -- 线程名列表(/proc/<pid>/task/<tid>/comm) -- */
void list_thread_comms(int pid, std::vector<std::string>& out);

/* -- 在目标进程可读映射里扫描字符串(找 frida/gum 这类内存特征) --
 * 返回 true = 命中;hit_addr 给首个命中地址,region 给所在映射路径。
 * max_bytes 限制总扫描量,防卡死(每页 4KB 粒度、可读映射)。 */
bool mem_scan_string(int pid, const char* needle, uint64_t max_bytes,
                     uint64_t* hit_addr, std::string* region);
/* 多特征一次扫描(魔改版 frida 要同时找明文/base64/自定义多个 needle,
 * 一遍内存走完,避免 N 次全量扫描)。命中时 hit 指向命中的那个 needle。 */
bool mem_scan_any(int pid, const char* const* needles, size_t nneedles,
                  uint64_t max_bytes, const char** hit, uint64_t* hit_addr,
                  std::string* region);

/* -- 监听端口 + 归属进程(LISTEN 态,反查 socket inode 得到 pid/cmdline) -- */
struct ListenPort {
    uint16_t port = 0;
    std::string owner;      // 归属进程 cmdline 首段(拿不到则空)
    int pid = 0;
};
void list_listening_ports(std::vector<ListenPort>& out);

/* -- /proc/<pid>/cmdline 遍历:进程名含 keyword? -- */
bool any_process_cmdline_contains(const char* keyword);
/* 遍历所有进程,找 cmdline 含 keyword 的进程,写入 pid+cmdline(最多 max 个) */
struct ProcHit { int pid; std::string cmdline; std::string comm; };
void find_processes(const char* keyword, std::vector<ProcHit>& out, size_t max);

/* -- Android 系统属性(封装 __system_property_get) -- */
std::string get_prop(const char* name);
/* 枚举全部系统属性(resetprop 改过/新加的也看得见),最多 max 条 */
void enumerate_props(std::vector<std::pair<std::string, std::string>>& out, size_t max);

/* -- USB 物理连接(内核 sysfs,不依赖 Java) 1=连着 0=没连 -1=未知 -- */
int usb_physically_connected();

/* -- popen 跑一条命令拿第一行输出(找不到命令返回空) -- */
std::string first_line_of(const char* cmd);

/* -- SHA-256 / MD5(纯 C 实现,零依赖;返回小写 hex) -- */
std::string sha256_hex(const uint8_t* data, size_t len);
std::string sha256_file_hex(const char* path);  // 失败返回空串
std::string md5_hex(const uint8_t* data, size_t len);
std::string md5_file_hex(const char* path);

/* -- 简易 ZIP 定位:取 APK 中第一个 META-INF 目录下的 v1 签名文件
 *    (.RSA/.DSA/.EC;stored 直读,deflate 则 inflate;需 HAVE_ZLIB)。
 *    返回 false = 打开失败或找不到签名块。 -- */
bool apk_first_signature(const char* apk_path, std::vector<uint8_t>& out);

/* -- APK 签名信息(v1 JAR / v2 / v3),含每套签名的证书 MD5 指纹 --
 *   v1: 解 PKCS#7 取第一张证书 DER;v2/v3: 解 APK Signing Block 取证书。
 *   md5 全小写 hex(64 位是 sha256;md5 是 32 位),与 Java
 *   PackageInfo.signatures 的 md5 语义一致。 */
struct ApkSignInfo {
    bool has_v1 = false, has_v2 = false, has_v3 = false;
    std::string v1_cert_md5, v2_cert_md5, v3_cert_md5;
    std::string v1_cert_sha256, v2_cert_sha256, v3_cert_sha256;
    std::string note;                  // 解析过程中的异常说明
};
bool apk_signature_info(const char* apk_path, ApkSignInfo& out);

/* -- base16 解析:hex 字符串 -> 字节(失败返回 false) -- */
bool hex_decode(const char* hex, std::vector<uint8_t>& out);

/* -- 环境事实(Java/JNI 回填;见 sec_detect_api.h) -- */
const sec_env_facts_t& env_facts();
void set_env_facts(const sec_env_facts_t* f);
bool env_has(uint32_t bit);                 // 该字段是否已由调用方提供

}  // namespace util
}  // namespace sec

/* ================= 子类工厂(各 det_*.cpp 实现,api.cpp 汇总) =================
 * extern "C" 是为了让符号名稳定、方便调试器辨认;返回堆对象,api 层管理。 */
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
sec::BaseDetector* sec_make_integrity_detector();
sec::BaseDetector* sec_make_ida_detector();
}

#endif /* SECDETECT_INTERNAL_H */
