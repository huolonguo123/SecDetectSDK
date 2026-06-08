/*
 * det_integrity.cpp — 检测项 11:代码完整性校验(内存 vs 磁盘)
 *
 * 这是"指令层"检测,和文件层的重打包(签名)、进程层的模块白名单
 * 差分(第 10 项)互补:
 *
 *   inline hook 改的是「运行中的内存」,不是磁盘文件——
 *   所以文件签名/哈希永远查不出 hook,必须拿内存和磁盘对拍。
 *
 * 原理链(面试要能讲全):
 *   1. mmap(file) 是「按需分页」+「写时复制(COW)」:
 *      没被写过的页读出来就是文件内容;
 *      一旦有人往 .text 写了跳转指令,kernel 把那页 COW 出去,
 *      该页的「内存内容」就与「文件同偏移内容」不再相等。
 *   2. /proc/<pid>/maps 每行的 offset 字段 = 这段映射的起点
 *      在文件中的偏移(映射时 mmap 的 offset 参数)。
 *      于是有恒等式:**内存 VA 的字节 == 磁盘文件 offset + (VA - map_start)
 *      处的字节**(在没被改写时成立)。
 *   3. 反过来:逐页比对不相等的地方 = 被改写过的地方,通常正好是
 *      被 hook 的函数入口(改 4~16 字节的跳板)。
 *      差异地址可以直接送 IDA:文件偏移 = off + (va - start)。
 *
 * 局限(诚实地写进报告):
 *   - 只对「文件映射」有意义:匿名可执行段([anon:dalvik-jit…])没有
 *     磁盘基线,要 opcode 扫描兜底;
 *   - 需要 root(或同 uid)才能读别的进程的 mem;跑在自己进程内
 *     查自己(产品形态)则不需要;
 *   - .data.rel.ro / .got 是 rw 段,不在本项范围(GOT hook 要单独
 *     与文件比对,属于下一步扩展);
 *   - 极少数 runner 会在启动后自我改写(如某些加固壳的运行时解密),
 *     生产上要先跑基线、只对差异做复核。
 */
#include "internal.h"

#include <fcntl.h>
#include <unistd.h>

namespace sec {

namespace {

constexpr size_t kChunk      = 4096;              /* 比对粒度:一页 */
constexpr uint64_t kPerMapCap = 8ULL * 1024 * 1024;   /* 单个映射最多比 8MB */
constexpr uint64_t kTotalCap  = 64ULL * 1024 * 1024;  /* 一次总预算 64MB   */
constexpr int kMaxReport      = 6;                /* 最多报 6 个差异点 */

bool trusted_no_compare(const std::string& p) {
    static const char* skip[] = {
        "/dev/", "/proc/", "/sys/", "memfd:", "anon_inode:",
    };
    for (const char* s : skip)
        if (p.compare(0, strlen(s), s) == 0) return true;
    return false;
}

}  // namespace

class IntegrityDetector : public BaseDetector {
public:
    const char* name() const override { return "integrity"; }
    int type() const override { return DETECT_INTEGRITY; }

    bool run(const char* input, Findings& f) override {
        int pid = util::target_pid(input);
        const char* who = (pid > 0) ? "integrity[pid]:" : "integrity:";

        std::vector<util::MapRegion> maps;
        if (!util::parse_maps(pid, maps)) {
            if (pid > 0 && !util::process_exists(pid))
                f.add("integrity: no such process pid %d", pid);
            else
                f.add("integrity: cannot read maps (permission denied, need root)");
            return false;
        }

        bool risk = false;
        uint64_t budget = kTotalCap;
        uint64_t total_bytes = 0;
        int regions = 0, skipped_unreadable = 0;
        int diffs_total = 0;
        std::vector<uint8_t> membuf(kChunk), filebuf(kChunk);
        std::string report;

        for (const auto& r : maps) {
            if (budget == 0) break;
            if (!r.is_exec() || r.anonymous() || r.path.empty()) continue;
            if (trusted_no_compare(r.path)) continue;
            if (r.end <= r.start) continue;

            int fd = open(r.path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) { skipped_unreadable++; continue; }
            ++regions;

            uint64_t cap = std::min<uint64_t>(r.end - r.start, std::min(kPerMapCap, budget));
            for (uint64_t va = r.start; va < r.start + cap; va += kChunk) {
                size_t want = (size_t)std::min<uint64_t>(kChunk, r.start + cap - va);
                if (!util::read_proc_mem(pid, va, membuf.data(), want)) continue;
                off_t foff = (off_t)(r.off + (va - r.start));
                ssize_t got = pread(fd, filebuf.data(), want, foff);
                if (got != (ssize_t)want) continue;      /* 文件变短/不可读,跳过 */

                if (memcmp(membuf.data(), filebuf.data(), want) != 0) {
                    /* 定位页内第一个差异字节,报出来方便直接去 IDA 对 */
                    size_t i = 0;
                    while (i < want && membuf[i] == filebuf[i]) ++i;
                    ++diffs_total;
                    risk = true;
                    if ((int)report.size() < 900 && diffs_total <= kMaxReport) {
                        auto B = [&](std::vector<uint8_t>& v, size_t k) -> unsigned {
                            return (i + k < want) ? v[i + k] : 0u;
                        };
                        char line[224];
                        snprintf(line, sizeof line,
                                 "%s code diff @va=0x%llx file=0x%llx %s "
                                 "(mem=%02x%02x%02x%02x disk=%02x%02x%02x%02x)",
                                 who, (unsigned long long)(va + i),
                                 (unsigned long long)(r.off + (va - r.start) + i),
                                 r.path.c_str(),
                                 B(membuf, 0), B(membuf, 1), B(membuf, 2), B(membuf, 3),
                                 B(filebuf, 0), B(filebuf, 1), B(filebuf, 2), B(filebuf, 3));
                        f.add("%s", line);
                    }
                }
                budget -= (budget > want) ? want : budget;
                total_bytes += want;
            }
            close(fd);
        }

        if (diffs_total > kMaxReport)
            f.add("%s ... %d more diff pages suppressed", who, diffs_total - kMaxReport);
        if (!risk)
            f.add("%s no code diff: %d exec regions / %llu bytes compared "
                  "vs on-disk file (%d unreadable skipped)",
                  who, regions, (unsigned long long)total_bytes, skipped_unreadable);
        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_integrity_detector() {
    return new sec::IntegrityDetector();
}
