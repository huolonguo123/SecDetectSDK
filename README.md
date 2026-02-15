# SecDetect SDK — Android 客户端安全检测(用户态 9 项 + TEE 扩展点)

对应《Android TEE 安全检测 SDK 整体设计说明》的落地实现。架构、接口、
返回码与设计文档一致;TEE 部分以"后端注入点"占位并明确标注,不假装
已接入安全世界。

- 语言 / 平台:C++17,NDK(r29 验证),ARM64 + ARM32(armeabi-v7a)
- 两个产物:`libsecsdk.so`(SDK 本体,给 JNI/App 集成)、`secdetect`(命令行 runner,实机验证)
- 对外接口:纯 C ABI,导出面锁死 4 个符号(version script)

```
include/sec_detect_api.h   公开 C ABI:枚举/返回码/secdetect()/TEE 注入点
src/internal.h             内部公共头:Findings 证据收集器、BaseDetector 基类、util 声明
src/util.cpp               取证工具:SHA-256(零依赖)、/proc 解析、端口、属性、迷你 ZIP
src/api.cpp                调度层:注册表(9 个子类)+ 参数校验 + 返回码归一
src/det_root.cpp           1 Root/Magisk
src/det_debugger.cpp       2 调试器 + IDA(android_server/gdbserver)
src/det_frida.cpp          3 Frida 注入/驻留
src/det_xposed.cpp         4 Xposed/LSPosed/Riru/Zygisk
src/det_emulator.cpp       5 QEMU 模拟器
src/det_vm.cpp             6 虚拟机 / 双开容器
src/det_repack.cpp         7 重打包(APK v1 签名指纹比对)
src/det_bootloader.cpp     8 Bootloader 解锁
src/det_usb.cpp            9 USB 调试
src/tee_stub.cpp           TEE 占位:后端函数指针注入 + 未集成状态
src/export.map             导出面白名单(4 个 C 符号)
demo/main.cpp              runner:secdetect all|root|7 <apk>|tee
build/arm64|v7a/           NDK 产物(secdetect 可执行 + libsecsdk.so)
```

## 一、对外接口(与设计文档一致)

```c
int secdetect(int detect_type, const char* input, char* output, size_t output_len);
```

- `detect_type`:枚举 1..9(见上表),`DETECT_ALL=0x7F` 全扫;
  全扫输出每行 = `编号|名字|证据`,未命中标 `(clean)`:
  `1|root|magisk data: /data/adb/magisk`、`2|debugger|(clean)`
- `input`:只读,仅重打包项必填 —— `"/data/app/.../base.apk"`(校准,打印指纹)
  或 `"/data/app/.../base.apk,<官方基线sha256>"`(比对);其余项传 NULL
- `output`:调用方分配,SDK 只写不分配;传 NULL 时 `output_len` 必须为 0(只取返回码)
- `output_len`:超长截断,尾部补 `~`

返回码:**-1 参数错误 / 0 未发现风险 / 1 检测到风险**(严格三值)。
命中时 output 是证据串,如:
`root: /system/xbin/su exists; magiskd: init.svc.magiskd=running`

架构(设计文档"二")落地:
每个检测项 = `BaseDetector` 的一个子类,只实现 `run()` 填证据;基类语义:
子类命中 → 返回 1 并把证据拷进 output;不命中 → 返回 0。
`Findings` 是证据收集器(内部 1KB 缓冲,自动加 `; ` 分隔、自动截断)。
`api.cpp` 的注册表持有 9 个子类单例,`secdetect()` 做参数校验后按类型
分发——检测逻辑与缓冲/返回码管理彻底分离。

## 二、编译(WSL)

```bash
NDK=/root/strongR/android-ndk-r29
cmake -S . -B build/arm64 -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64 -j
# ARM32 同命令,ABI 换 armeabi-v7a,-B build/v7a
```

产物已 strip;`libsecsdk.so` 导出面 = 4 个 `secdetect*` 符号
(动态链 libc++_shared + version script 双重收口)。

## 三、9 项检测:原理、证据、局限(设计文档"三"逐个模块)

> 通用纪律:所有证据都是"旁证",任何单项都可被针对性伪装;产品价值在
> 多项交叉 + 周期性执行 + 与 TEE 强校验配合。每项代码头注释里写了
> "面试要能讲"的攻防关系。

1. **Root/Magisk** —— 三级证据:
   L1 su 常见路径(`/system/bin/su` 等 8 个)—— 老式 root/SuperSU 残留
   (Magisk 30 实测不在这些路径,仅兼容旧机);
   L2 `/debug_ramdisk/magisk` —— Magisk 26+ 修补 boot 后留在 ramdisk 的
   载荷,普通 uid 也能 stat(**实机验证:非 root 形态下本项依然命中**,
   新版 Magisk 的主证据);
   L3 root 权限下穿透 /data 查 `/data/adb/magisk`、`magisk.db`、模块目录
   (最深一层,App 沙盒看不到,留给 su/adb root 场景)。
   局限:su 改名可绕 L1;DenyList 只对白名单进程隐藏痕迹;boot 载荷
   理论上可被 Magisk 模块改名抹除——强校验仍需 TEE 启动链证明。

2. **调试器 / IDA** —— 核心是内核记账 `TracerPid`(gdb/lldb/IDA/jdb 动态
   调试都走 ptrace,附加期间 /proc/self/status 必留 pid,最难伪造);
   旁证:android_server 文件与默认端口 23946、gdbserver 5039、进程名。
   局限:只反映"此刻",调试器可快速 附加→读→摘除 规避单次采样,产品要轮询。

3. **Frida** —— 双形态:frida-server(进程 cmdline 含 frida、27042 端口、
   `/data/local/tmp/re.frida.server` socket)与注入 agent(自身 maps 出现
   frida/linjector/gadget = "有人往我肚子里塞了代码"的铁证)。
   局限:改名、随机端口、反射内存加载(不进 maps 路径)均可绕,需叠内存
   特征扫描与线程名(gum-js-loop)检测。

4. **Xposed/LSPosed** —— 注入进程视角:maps 关键词
   xposed/lspd/edxp/riru/zygisk/tai-chi;系统视角:`/system/framework/
   XposedBridge.jar`、root 下 `/data/adb/modules` 模块名、pm 查框架包。
   局限:只查自身进程注入;模块可改名;与 root 检测有交集(zygiskd)。

5. **模拟器(QEMU)** —— 找"真机物理上不存在的硬件":goldfish/ranchu
   平台名、`/dev/goldfish_pipe`、`/dev/qemu_pipe`、qemud 二进制、
   `ro.kernel.qemu=1`。改 prop 藏得住属性,藏不住 /dev 节点与系统镜像内容。

6. **虚拟机/双开** —— VM 形态:waydroid/anbox/cuttlefish/vsoc 的硬件属性;
   双开形态:自身 maps 里宿主路径(virtualapp/com.lody.virtual/tai-chi 等);
   cgroup 出现 docker/kubepods(Android 原生不可能)。
   局限:双开框架普遍做痕迹清理,maps 关键词会漏;生产要叠
   "进程真实 uid/数据目录 vs 包名"的交叉校验(由 Java 层提供 context)。

7. **重打包** —— 自研迷你 ZIP 解析:扫 EOCD→遍历 Central Directory→
   定位 `META-INF/` 下 v1 签名块(.RSA/.DSA/.EC)→ 读原字节(stored 直读 /
   deflate 用 zlib 解)→ SHA-256,与官方基线比对;签名块整体消失也算风险。
   两种用法:不带基线=校准(把当前指纹交给 CI 固化为基线);带基线=判定。
   局限:只覆盖 v1 签名;纯 v2/v3 APK 没有 META-INF 签名文件,产品里应改用
   Java 层 `PackageManager.GET_SIGNING_CERTIFICATES` 拿证书 digest 做基线。

8. **Bootloader 解锁** —— 读 AVB 状态属性:`ro.boot.verifiedbootstate`
   (green=锁+验证链完整;orange=解锁;red=验证失败)、`vbmeta.device_state`、
   `ro.boot.flash.locked`、MTK `ro.secureboot.lockstate`。
   为什么重要:解锁是刷 Magisk/LSPosed/hook 环境的地基。
   局限:属性可被 resetprop 伪造 —— 强校验必须放 TEE(attestation/
   RPMB),这正是设计文档 TEE 部分的动机,见第四节。

9. **USB 调试** —— `persist.sys.usb.config`/`sys.usb.config` 含 "adb"
   (当前 USB 功能挂 adb)、`ro.debuggable=1`(eng/userdebug 固件)、
   5555 监听(网络 adb)。
   局限:配置开关 ≠ 当前有会话;生产可再叠 Settings.Global adb_enabled。

## 四、TEE 扩展点(占位,诚实标注)

普通 App 用户态拿不到 TEE 通道;真实 TA 需要厂商 SDK 与签名,个人项目
无法落地。因此 SDK 把边界切在后端抽象:

```c
typedef int (*tee_attest_fn)(char* out, size_t out_len);
void secdetect_tee_set_backend(tee_attest_fn fn);   // 集成方注入 GP client 实现
int  secdetect_tee_attest(char* output, size_t output_len); // 未集成返回 1
```

`tee_stub.cpp` 是默认实现:无后端时明确返回"未集成",不假装安全。
架构文档里"bootloader 读取/磁盘 ELF 基线/opcode 摘要放安全世界"的
设计意图,在代码里体现为:用户态检测项全部标注了"哪些证据会被注入
篡改、哪些必须上 TEE",产品化时把对应判定换成 TA 返回值即可。

## 五、实机验证(PowerShell,手机连 adb)

```powershell
# 1) 推送 runner(路径按实际;手机是 root 机)
adb push "D:\android detector\build\arm64\secdetect" /data/local/tmp/
adb shell chmod +x /data/local/tmp/secdetect

# 2) 全扫(建议 su -c 拿 root 权限,能穿透 /data 查 Magisk 深层特征;
#    首次会在手机弹 Magisk 授权框,点允许)
adb shell su -c /data/local/tmp/secdetect all

# 3) 单项 & repack 用法
adb shell su -c /data/local/tmp/secdetect root
adb shell su -c /data/local/tmp/secdetect 2
adb shell su -c "/data/local/tmp/secdetect 7 /data/app/com.android.chrome-*/base.apk"
```

在自己那台"Magisk + TrickyStore + 解锁"的 Pixel 7 上,预期:
`1|root`、`8|bootloader`、`9|usb_debug` 命中(这正是检测器在工作的证据);
frida-server 开着时 `3|frida` 也会命中;没有的项(xposed/emulator/vm)
应为 `0`。把输出贴回来即可核对每条证据是否合理。

### 实机验证记录(2026-09-06,Pixel 7 / Magisk 30.7 / TrickyStore)

**形态一:su -c(root,euid=0)—— 三层证据全开**
```
1|root|magisk data: /data/adb/magisk; magisk data: /data/adb/magisk.db
8|bootloader|vbstate: ro.boot.verifiedbootstate=orange; vbmeta: ...=unlocked; flash: ro.boot.flash.locked=0
9|usb_debug|usb: persist.sys.usb.config=adb (adb enabled); ...
```

**形态二:普通 adb shell(euid=2000,等价 App 沙盒)—— L3 不可见,靠 L2**
```
1|root|magisk: /debug_ramdisk/magisk (patched boot ramdisk)
8|bootloader|... (属性全局可读,照常命中)
9|usb_debug|...
```
其余项(debugger/frida/xposed/emulator/vm)两种形态下均 (clean),无一次误报。

**形态三:frida 驻留检测(普通 adb shell,euid=2000;frida-server 以 root 在跑)**
```
3|frida|proc: frida-server process running
```
普通 uid 也能遍历到 root 进程的 cmdline,SELinux 不挡 /proc 的 cmdline 读取。

**形态四:frida 注入检测(secdetect loop 模式,frida -p attach 注入)**
```
t=..34  frida=1 [proc: frida-server process running]                      ← 注入前
t=..38  frida=1 [proc: ...; maps: injected module contains 'frida']       ← attach 后 2s 内命中
t=..40+ frida=1 [同上,持续命中]
        debugger 恒 0
```
结论:agent 的 so 映射是"驻留证据",注入后一直可查;TracerPid 只是注入
瞬间的"窗口证据"(frida 注入完松开 ptrace,debugger 检测看不到)。命中
延迟 = 轮询周期(2s)。maps 证据难绕:可执行代码必有映射,改名/伪装路径
可绕字符串匹配但绕不过"映射存在"这一事实,反射内存加载则需内存特征扫描。

**踩坑修正(检测特征会随对抗版本过时)**:初版把 `init.svc.magiskd=running`
当非 root 主证据——实测 Magisk 30.7 的 getprop 里该属性已不存在(守护进程
不再注册为 init 服务),su 路径表同样全空(Magisk 不在 /system/xbin 放 su)。
经实机验证 `/debug_ramdisk/magisk`(boot 修补载荷,目录对 other 开放 x、
文件 755,普通 uid 可 stat)后,将其升为 L2 主证据,旧特征降级为兼容。
教训:检测特征必须"实测驱动",不能照抄旧文档;每代对抗版本都要重验证。

## 六、已知边界(写报告/面试时主动讲,别等人问)

1. 全部是用户态旁证;对抗者用 root 后能改属性、改名、改端口、内存加载
   绕过大部分单项 —— 所以产品形态是"交叉 + 周期 + 服务端聚合"。
2. v1 签名指纹检测覆盖不了 v2/v3-only 的现代 APK(代码已注释替代方案)。
3. 检测自身进程的 maps 只能发现注入自身的模块(遍历他人进程 maps 是
   产品化方向,骨架已留 cmdline 遍历原语)。
4. TEE 通道为占位;bootloader/基线/opcode 的强校验是设计文档里
   "放安全世界"的部分,代码边界已切好,等厂商 TA。
5. `pm list packages` 类查询慢(秒级),SDK 集成时应由上层 Java 一次取
   全量包列表再过滤,避免每次检测都 fork 进程。
