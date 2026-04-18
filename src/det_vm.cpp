/*
 * det_vm.cpp — 检测项 6:虚拟机 / 双开容器(非 QEMU 形态)
 *
 * 与"模拟器"的区别:模拟器是完整 QEMU 虚拟机,自带 android
 * 系统;这里的 VM 指在真机系统之上再叠一层"虚拟环境":
 *
 *   a) 容器化虚拟机:Waydroid / Anbox / Cuttlefish(Google 的
 *      VM 形态设备),特征是 ro.hardware / vendor 相关 prop、
 *      binder 域、/dev 特殊节点;
 *   b) 双开/分身类:VirtualApp、太极、平行空间、小米分身等,
 *      宿主 App 在自己的进程里加载目标 App 的 dex/so——
 *      被双开的 App 进程 maps 里会出现宿主包名路径
 *      (/data/user/0/com.lody.virtual/... 或 virtual 关键词)。
 *
 * 局限:双开框架这几年普遍做"痕迹清理",单靠 maps 关键词会有
 * 漏网;生产环境应叠加 1) 进程真实数据目录与包名的对应校验
 * (由 Java 层提供 context 信息);2) uid/包名校验;3) 系统属性
 * 与 cgroup 一致性。本项作为用户态可落地的第一层。
 */
#include "internal.h"

namespace sec {

class VmDetector : public BaseDetector {
public:
    const char* name() const override { return "vm"; }
    int type() const override { return DETECT_VM; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);   /* input="pid:N" 扫目标进程,空=自己 */
        const char* who = (pid > 0) ? "vm[pid]:" : "vm:";

        /* 1) VM 形态 prop(先读一次,再对每个厂商名匹配) */
        std::string hw = util::get_prop("ro.hardware");
        std::string dev = util::get_prop("ro.product.device");
        std::string brd = util::get_prop("ro.product.board");
        static const char* vms[] = {"waydroid", "anbox", "cuttlefish", "vsoc"};
        for (const char* v : vms) {
            if (hw.find(v) != std::string::npos || dev.find(v) != std::string::npos ||
                brd.find(v) != std::string::npos) {
                f.add("prop: hw/device/board contains '%s'", v);
                risk = true;
                break;
            }
        }

        /* 2) 双开容器:目标进程被宿主加载的痕迹(maps 路径关键词) */
        static const char* host_kw[] = {
            "virtualapp", "com.lody.virtual",  // VirtualApp
            "tai-chi", "taichi",               // 太极
            "com.lbe.parallel",                // 平行空间
            "multi-app", "miui.multi",         // MIUI 分身
        };
        for (const char* k : host_kw) {
            if (util::maps_path_contains(pid, k)) {
                f.add("%s maps: virtual host '%s'", who, k);
                risk = true;
            }
        }

        /* 3) 通用容器旁证:cgroup 里出现 docker/kubepods
         *    (Android 原生环境不会有;真机上出现 = 跑在容器里) */
        std::string cg;
        if (util::read_small_file("/proc/self/cgroup", cg)) {
            if (cg.find("docker") != std::string::npos ||
                cg.find("kubepods") != std::string::npos) {
                f.add("cgroup: container cgroup detected");
                risk = true;
            }
        }

        return risk;
    }
};

}  // namespace sec

extern "C" sec::BaseDetector* sec_make_vm_detector() {
    return new sec::VmDetector();
}
