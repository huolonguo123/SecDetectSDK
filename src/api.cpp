/*
 * api.cpp — 统一调度层:注册表 + secdetect() 入口
 *
 * 职责边界:
 *   - 参数校验(枚举合法性 / output 与 len 配套 / repack 的 input);
 *   - 从注册表挑检测器,跑 run(),把 Findings 拷进 output(截断);
 *   - 返回码归一:-1 / 0 / 1。
 * 检测逻辑全部在子类里,本文件不掺和任何"怎么查"。
 */
#include "internal.h"

#include <memory>
#include <vector>

namespace {

using sec::BaseDetector;
using sec::Findings;

/* ---- 注册表:进程内只构造一次,12 个子类全量登记 ---- */
struct Registry {
    std::vector<BaseDetector*> items;
    Registry() {
        items.push_back(sec_make_root_detector());
        items.push_back(sec_make_debugger_detector());
        items.push_back(sec_make_frida_detector());
        items.push_back(sec_make_xposed_detector());
        items.push_back(sec_make_emulator_detector());
        items.push_back(sec_make_vm_detector());
        items.push_back(sec_make_repack_detector());
        items.push_back(sec_make_bootloader_detector());
        items.push_back(sec_make_usb_detector());
        items.push_back(sec_make_module_detector());
        items.push_back(sec_make_integrity_detector());
        items.push_back(sec_make_ida_detector());
    }
    ~Registry() {
        for (BaseDetector* d : items) delete d;
    }
    BaseDetector* by_type(int t) const {
        for (BaseDetector* d : items)
            if (d->type() == t) return d;
        return nullptr;
    }
};

Registry& registry() {
    static Registry r;
    return r;
}

/* ---- output 写入:自带截断,末尾 '~' 表示"还有内容被切了" ---- */
void write_out(char* out, size_t cap, const std::string& s) {
    if (!out || cap == 0) return;
    if (s.size() >= cap) {
        if (cap >= 2) {
            memcpy(out, s.data(), cap - 2);
            out[cap - 2] = '~';
            out[cap - 1] = '\0';
        } else {
            out[0] = '\0';
        }
    } else {
        memcpy(out, s.data(), s.size());
        out[s.size()] = '\0';
    }
}

/* ---- 单项检测(内部共用) ---- */
int run_single(BaseDetector* d, const char* input, char* out, size_t outlen) {
    Findings f;
    bool risk = d->run(input, f);
    if (out && outlen) write_out(out, outlen, f.c_str());
    return risk ? SEC_RISK : SEC_OK;
}

bool valid_type(int t) {
    if (t == DETECT_ALL) return true;
    return registry().by_type(t) != nullptr;
}

/* repack 的 input 形态:"/path/to.apk[,baseline]";apk 部分必须存在。
 * 注意:input 可以为空 —— 那时 repack 会改用 Java 回填的
 * SEC_FACT_APK_PATH(见 det_repack.cpp 头注释)。 */
bool repack_input_ok(const char* input) {
    if (!input || !*input) return false;
    std::string paths(input);
    size_t comma = paths.find(',');
    if (comma != std::string::npos) paths.erase(comma);
    /* 支持 '|' 分隔的多路径:base APK + 各 split APK(或多基线)。
     * **每一段都必须存在**,否则参数不合法(见 sec_detect_api.h 的说明)。 */
    size_t start = 0;
    bool found = false;
    while (start <= paths.size()) {
        size_t end = paths.find('|', start);
        if (end == std::string::npos) end = paths.size();
        std::string apk = paths.substr(start, end - start);
        /* 去掉首尾空白(含 \r\n:Windows 侧拼出来的路径可能带) */
        size_t b = apk.find_first_not_of(" \t\r\n");
        size_t e = apk.find_last_not_of(" \t\r\n");
        if (b == std::string::npos) return false;
        apk = apk.substr(b, e - b + 1);
        if (!sec::util::file_exists(apk.c_str())) return false;
        found = true;
        if (end == paths.size()) break;
        start = end + 1;
    }
    return found;
}

/* ---- DETECT_ALL:逐项跑,命中/有信息才写一行。
 *      input 传给每一类检测项:pid-based 的项自己解析 "pid:N",
 *      repack 把它当 apk 路径(传空则用 env facts)。 ---- */
int run_all(const char* input, char* out, size_t outlen) {
    std::string all;
    int worst = SEC_OK;
    for (BaseDetector* d : registry().items) {
        Findings f;
        bool risk = d->run(input, f);
        if (!all.empty()) all += '\n';
        char hdr[40];
        snprintf(hdr, sizeof hdr, "%d|%s|", d->type(), d->name());
        all += hdr;
        if (f.empty() && !risk) {
            all += "(clean)";
        } else {
            /* ★ 单项证据设上限:保证"每项一行"的承诺在调用方缓冲较小时也成立。
             * 真机实测(2026-09):第 1 项(root/Magisk)证据单独就 ~1.7KB,以前会把整个输出缓冲
             * 吃掉,导致 all 的第 7~12 项整段消失(看起来像"没检测",实则是被截断)。 */
            std::string ev = f.c_str();
            const size_t kMaxPerItem = 600;
            if (ev.size() > kMaxPerItem) {
                ev.resize(kMaxPerItem - 1);
                ev += '~';
            }
            all += ev;
        }
        if (risk) worst = SEC_RISK;
    }
    write_out(out, outlen, all);
    return worst;
}

}  // namespace

extern "C" {

SEC_API void secdetect_version(char* output, size_t output_len) {
    if (output && output_len) {
        size_t n = strlen(SECDETECT_VERSION);
        if (n >= output_len) n = output_len - 1;
        memcpy(output, SECDETECT_VERSION, n);
        output[n] = '\0';
    }
}

SEC_API int secdetect(int detect_type, const char* input, char* output, size_t output_len) {
    /* ---- 参数校验 ---- */
    if ((output == nullptr) != (output_len == 0))   // 空指针配非零长度,反之亦然
        return SEC_ERR_PARAM;
    if (output && output_len == 0)
        return SEC_ERR_PARAM;
    if (!valid_type(detect_type))
        return SEC_ERR_PARAM;

    if (detect_type == DETECT_ALL)
        return run_all(input, output, output_len);

    BaseDetector* d = registry().by_type(detect_type);

    /* repack 给了 input 但路径打不开 → 参数错误(没给 input 则走 env facts 自动模式) */
    if (d->type() == DETECT_REPACK && input && *input && !repack_input_ok(input)) {
        if (output && output_len) {
            std::string msg = "repack: input not accessible, usage: "
                              "<apk_path>[,<md5|sha256>[|<more>]]  or leave empty and "
                              "fill SEC_FACT_APK_PATH from Java";
            write_out(output, output_len, msg);
        }
        return SEC_ERR_PARAM;
    }

    return run_single(d, input, output, output_len);
}

}  // extern "C"
