/*
 * det_vm.cpp — 检测项 6:虚拟机 / 双开多开(核心:同进程多应用)
 *
 * 与"模拟器"(第 5 项,QEMU 完整虚拟机)的区别:这里指在**真机系统
 * 之上再叠一层虚拟环境**:
 *   a) 容器化 VM:Waydroid / Anbox / Cuttlefish / redroid / 云手机;
 *   b) ★ 双开 / 多开 / 分身 / 插件化:VirtualApp、平行空间、双开助手、
 *      太极、MIUI 分身、VMOS……——
 *      它们的共同形态是「宿主进程里加载了别人的 APK」:
 *
 *        宿主 App 进程(/data/app/com.host-xxx/base.apk)
 *          ├─ 加载 guest1 的 APK: /data/user/0/com.host/virtual/.../com.guest1/base.apk
 *          ├─ 加载 guest2 的 APK
 *          └─ bind mount 其它应用的数据目录
 *
 * ================== 核心判据:一个进程里有几个应用 ==================
 * 正常 App 进程只会映射「自己」的 APK / so / oat。所以:
 *
 *   1) 扫 maps,把所有「应用来源路径」解析成包名:
 *        /data/app/[~~xxx/]com.foo-<hash>/…
 *        /data/user/<n>/<pkg>/…
 *        /data/data/<pkg>/…
 *      出现 **≥2 个不同包名** → 同进程托管了多个应用 = 双开/多开。
 *   2) 数据目录归属:进程映射了别的包的数据目录(VirtualApp 把 guest
 *      数据目录 bind 进宿主)。
 *   3) mount 视图:mountinfo 里出现 <宿主数据目录>/virtual/... 的
 *      bind mount(VirtualApp 系的标志结构)。
 *   4) Java 回填:getPackagesForUid(myUid()).size() > 1(同一 uid
 *      下挂了多个包),或 context.getPackageCodePath() 与当前进程
 *      不一致 —— 这一条连"同名双开(同包名不同实例)"也能抓。
 *
 * 局限:双开框架会做痕迹清理(隐藏 maps 里的 guest 路径),所以第 4 类
 * (Java 侧 uid→包列表)是必要补充;VMOS 那种"VM 里再跑一个 Android"
 * 属于第 a 类,主要靠 prop/设备节点。
 */
#include "internal.h"

#include <set>

namespace sec {

namespace {

/* 双开/插件化框架的包名与路径特征(命中说明它是"宿主") */
const char* kCloneKeywords[] = {
    "com.lody.virtual",        /* VirtualApp 原版            */
    "io.virtualapp",           /* VirtualApp 工作室          */
    "com.lbe.parallel",        /* 平行空间                   */
    "com.excelliance.dualaid", /* 双开助手                   */
    "com.polestar.clone",      /* 分身大师                   */
    "com.miui.multi",          /* MIUI 分身                  */
    "com.qihoo.replugin",      /* 360 RePlugin(插件化)     */
    "com.didi.virtualapk",     /* VirtualAPK(插件化)       */
    "com.tencent.shadow",      /* 腾讯 Shadow(插件化)      */
    "tai-chi", "taichi",       /* 太极                       */
    "com.vmos",                /* VMOS(整机虚拟)           */
    "virtual",                 /* VirtualApp 的 virtual 目录 */
    "parallel", "clone", "multi-app",
};

/* VM/云手机形态的 prop 特征 */
const char* kVirtualProps[] = {
    "ro.hardware", "ro.product.device", "ro.product.board",
    "ro.product.brand", "ro.build.fingerprint",
};
const char* kVirtualPropVals[] = {
    "waydroid", "anbox", "cuttlefish", "vsoc", "redroid", "vmos", "llvmpipe",
};

/* 从 maps 路径里抠出"应用包名" */
std::string pkg_from_app_path(const std::string& p) {
    /* /data/app/[~~<hash>/]<pkg>-<suffix>/... */
    size_t pos = p.find("/data/app/");
    if (pos != std::string::npos) {
        std::string rest = p.substr(pos + strlen("/data/app/"));
        size_t slash = rest.find('/');
        std::string seg = rest.substr(0, slash);
        if (seg.rfind("~~", 0) == 0 && slash != std::string::npos) {
            std::string rest2 = rest.substr(slash + 1);
            size_t slash2 = rest2.find('/');
            seg = rest2.substr(0, slash2);
        }
        size_t dash = seg.rfind('-');
        if (dash != std::string::npos) seg = seg.substr(0, dash);
        return seg;
    }
    /* /data/user/<n>/<pkg>/... 与 /data/data/<pkg>/... */
    for (const char* pre : {"/data/user/", "/data/data/"}) {
        size_t at = p.find(pre);
        if (at == std::string::npos) continue;
        std::string rest = p.substr(at + strlen(pre));
        if (strcmp(pre, "/data/user/") == 0) {
            size_t slash = rest.find('/');
            if (slash == std::string::npos) continue;
            rest = rest.substr(slash + 1);
        }
        size_t slash = rest.find('/');
        std::string seg = rest.substr(0, slash);
        if (seg.empty() || seg[0] == '\0') continue;
        return seg;
    }
    return {};
}

/* 本进程"自己"的包名:cmdline 第一段(去掉 :process 后缀) */
std::string self_package(int pid) {
    std::string cmd = util::proc_read(pid, "cmdline");
    if (cmd.empty()) return {};
    size_t end = cmd.find('\0');
    std::string first = cmd.substr(0, end);
    size_t colon = first.find(':');
    if (colon != std::string::npos) first.erase(colon);
    /* 只有像包名的才要(dot 分隔) */
    if (first.find('.') == std::string::npos) return {};
    return first;
}

bool looks_like_pkg(const std::string& s) {
    if (s.size() < 4) return false;
    if (s.find('.') == std::string::npos) return false;
    for (char c : s)
        if (!(isalnum((unsigned char)c) || c == '.' || c == '_')) return false;
    return true;
}

}  // namespace

class VmDetector : public BaseDetector {
public:
    const char* name() const override { return "vm"; }
    int type() const override { return DETECT_VM; }

    bool run(const char* input, Findings& f) override {
        bool risk = false;
        int pid = util::target_pid(input);
        const char* who = (pid > 0) ? "vm[pid]:" : "vm:";

        /* ---------- a) 容器化 VM 形态(prop) ---------- */
        for (const char* pn : kVirtualProps) {
            std::string v = util::get_prop(pn);
            if (v.empty()) continue;
            std::string low = v;
            for (auto& c : low) c = (char)tolower((unsigned char)c);
            for (const char* need : kVirtualPropVals)
                if (low.find(need) != std::string::npos) {
                    f.add("prop: %s=%s (~'%s')", pn, v.c_str(), need);
                    risk = true;
                    break;
                }
        }

        /* ---------- b) 双开/插件化框架痕迹(maps 路径关键词) ---------- */
        std::vector<util::MapRegion> maps;
        bool maps_ok = util::parse_maps(pid, maps);
        if (maps_ok) {
            for (const auto& r : maps) {
                if (r.path.empty() || r.path[0] == '[') continue;
                /* ★ 伪文件系统路径(/dev、/proc、/sys)每个进程都一样,不可能是双开/插件化痕迹。
                 * 实测坑(2026-09 真机 Pixel 7 / Android 13):关键词 'virtual' 会命中
                 *   /dev/__properties__/u:object_r:virtual_ab_prop:s0   (AOSP virtual A/B,系统自带)
                 *   /dev/__properties__/u:object_r:virtualizationservice_prop:s0 (AVF 服务属性)
                 * 而 /dev/__properties__ 每个进程必映射 → 不跳过就必误报。 */
                if (r.path.rfind("/dev/", 0) == 0 || r.path.rfind("/proc/", 0) == 0 ||
                    r.path.rfind("/sys/", 0) == 0) continue;
                std::string low = r.path;
                for (auto& c : low) c = (char)tolower((unsigned char)c);
                for (const char* k : kCloneKeywords) {
                    if (low.find(k) != std::string::npos) {
                        f.add("%s maps: clone/plugin framework '%s' in %s", who, k, r.path.c_str());
                        risk = true;
                        break;
                    }
                }
            }
        }

        /* ---------- c) ★ 核心:同一进程里出现了几个应用 ---------- */
        if (maps_ok) {
            std::set<std::string> pkgs;
            std::set<std::string> data_dirs;
            for (const auto& r : maps) {
                if (r.path.empty() || r.path[0] == '[') continue;
                std::string pkg = pkg_from_app_path(r.path);
                if (!pkg.empty() && looks_like_pkg(pkg)) pkgs.insert(pkg);
                /* guest 数据目录被 bind 进本进程(maps 里直接可见) */
                if (r.path.find("/virtual/") != std::string::npos)
                    data_dirs.insert(r.path);
            }
            std::string self = self_package(pid);
            if (!self.empty()) pkgs.erase(self);

            if (pkgs.size() >= 2) {
                std::string list;
                int n = 0;
                for (const auto& p : pkgs) {
                    list += (list.empty() ? "" : ",") + p;
                    if (++n >= 6) break;
                }
                f.add("%s same process hosts %zu apps: %s "
                      "(双开/多开:one process = multiple apps)", who, pkgs.size(), list.c_str());
                risk = true;
            } else if (pkgs.size() == 1) {
                f.add("%s process maps another app's package: %s (self=%s)",
                      who, pkgs.begin()->c_str(), self.empty() ? "?" : self.c_str());
                risk = true;
            }
            for (const auto& d : data_dirs) {
                f.add("%s guest data dir mapped: %s", who, d.c_str());
                risk = true;
                break;
            }

            /* d) mountinfo 里宿主数据目录的 bind mount(VirtualApp 结构)
             * ★ 只认 <宿主数据目录>/virtual/... 这个结构本身。
             *   曾经同时匹配 "/data/user/",真机实测(2026-09 Pixel 7 / Android 13)发现
             *   /data/user/0 是**系统自带的 bind mount**(shell 与 su 命名空间里都有:
             *   "113 111 254:44 /data /data/user/0 … - f2fs /dev/block/dm-44")
             *   → 那条件在每台原生机上都命中,是纯粹的误报;设备上 "/virtual/" 计数为 0。 */
            std::string mi = util::proc_read(pid, "mountinfo");
            const char* p = mi.c_str();
            int shown = 0;
            while (p && *p && shown < 3) {
                const char* eol = strchr(p, '\n');
                std::string line(p, eol ? (size_t)(eol - p) : strlen(p));
                p = eol ? eol + 1 : nullptr;
                if (line.find("/virtual/") != std::string::npos) {
                    f.add("%s mountinfo bind: %s", who, line.c_str());
                    risk = true;
                    ++shown;
                }
            }
        }

        /* ---------- e) 通用容器旁证 ---------- */
        std::string cg = util::proc_read(pid, "cgroup");
        if (cg.find("docker") != std::string::npos ||
            cg.find("kubepods") != std::string::npos) {
            f.add("cgroup: container cgroup detected");
            risk = true;
        }

        /* ---------- f) Java 回填:同一 uid 下的包数量 ---------- */
        if (util::env_has(SEC_FACT_PKG_COUNT)) {
            int n = util::env_facts().pkg_count_for_uid;
            if (n > 1) {
                f.add("java: getPackagesForUid(myUid) 返回 %d 个包(>1 = 双开/多开)", n);
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
