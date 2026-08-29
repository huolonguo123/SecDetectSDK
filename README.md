# SecDetectSDK

Android 客户端安全检测 SDK(C/C++),在 App 进程内做 **12 项**运行环境风险检测:
Root/Magisk、调试器、Frida、Xposed、模拟器、虚拟机/双开、重打包、Bootloader(含 TEE 密钥证明)、
USB 调试、非白名单模块注入、**代码完整性(内存 vs 磁盘)**、**IDA 调试服务**。

对外暴露纯 C ABI,单函数入口;可集成进 Android App(JNI + Java 辅助类),也可用附带的命令行工具单独运行。

## 检测项

| # | 检测 | 名称 | 说明 |
|---|------|------|------|
| 1 | Root / Magisk | `root` | su 路径、boot 载荷、**属性全量枚举**、**mount namespace 差分(反隐藏)**、SELinux 域 |
| 2 | 调试器 | `debugger` | TracerPid + ptrace 停止态、全量调试器进程名单(gdb/lldb/jdb/…)、调试端口+归属反查、libjdwp |
| 3 | Frida | `frida` | 进程/端口/落盘物、模块名、**线程名**、**memfd/匿名可执行映射**、**内存字符串扫描(含魔改版 base64 特征)** |
| 4 | Xposed / LSPosed | `xposed` | 框架注入痕迹(Riru/Zygisk/EdXp/太极/RePlugin) |
| 5 | 模拟器 | `emulator` | QEMU 属性、**ARM→x86 转译层(houdini/ndk_translation)**、厂商私有库、/dev 节点、cmdline/tty/cpuinfo、Java 传感器与 GL_RENDERER;**`/dev/kvm` 需"无 AVF"才判风险**(Android 13+ Pixel 原生带 pKVM) |
| 6 | 虚拟机 / 双开 | `vm` | **同进程多应用(包名差分)**、双开框架映射、guest 数据目录、mountinfo(只认 `/virtual/` 结构)、同 uid 包数量;maps 关键词扫描**跳过伪文件系统路径** |
| 7 | 重打包 | `repack` | **v1/v2/v3 三套签名全解析**,与基线 **MD5/SHA-256** 指纹比对(证书级,对齐 keytool/apksigner) |
| 8 | Bootloader | `bootloader` | AVB 属性 + **Google Key Attestation** 字段(deviceLocked/verifiedBootState,TEE 填)+ **验证侧:逐级验签 / 根信任锚 / challenge 回验(客户端自检,权威判定在服务端)** |
| 9 | USB 调试 | `usb_debug` | **sysfs 物理连接** + **Java 的 ADB_ENABLED/开发者选项** + usb config/网络 adb |
| 10 | 模块注入 | `module` | 可执行模块白名单差分 + `(deleted)` 映射(注入手法) |
| 11 | 代码完整性 | `integrity` | 内存映射 vs 磁盘文件同偏移逐字节比对(inline hook 的唯一直接证据) |
| 12 | IDA 调试服务 | `ida` | android_server/dbgsrv 落盘物、进程、23946 端口+归属、TracerPid 归属、内存特征 |

所有检测均为用户态取证,单项都可被针对性绕过,需组合使用;第 8 项提供了不可伪造的 TEE 通道。

## 接口

```c
int  secdetect(int detect_type, const char* input, char* output, size_t output_len);
void secdetect_version(char* output, size_t output_len);
void secdetect_set_env_facts(const sec_env_facts_t* facts);   /* Java/JNI 回填环境事实 */
void secdetect_get_env_facts(sec_env_facts_t* out);
```

- `detect_type`:检测项编号 **1–12**,`DETECT_ALL(0x7F)` 全扫(每项一行输出)
- `input`:只读入参。仅重打包(7)必填(APK 路径);可扫其它进程的项支持 `"pid:<pid>"`;其余传 `NULL`
- `output`:调用方分配的缓冲区,SDK 只写不分配;超长自动截断(尾部 `~`)
- 返回码:`-1` 参数错误 / `0` 未发现风险 / `1` 检测到风险

### 环境事实回填(为什么需要)

USB 调试开关、传感器数量、GL_RENDERER、同 uid 包数量、Key Attestation 结果**只有 Java 能拿到**,
native 侧不做猜测,而是由一个显式结构回填:

```c
sec_env_facts_t f = {0};
f.provided  = SEC_FACT_ADB_ENABLED | SEC_FACT_USB_CONNECTED;
f.adb_enabled = 1; f.usb_connected = 1;
secdetect_set_env_facts(&f);
```

未回填的字段按"未知"处理(`provided` 位图保证不误报)。

**重打包检测也能免传路径**:Java 回填

```c
f.provided |= SEC_FACT_APK_PATH;       /* context.getApplicationInfo().sourceDir,多 split 用 '|' */
f.provided |= SEC_FACT_APK_BASELINE;   /* 官方指纹基线(CI 固化/服务端下发),多基线用 '|' */
```

之后 `secdetect(DETECT_REPACK, NULL, ...)` 就会自己找到 APK 并按基线判定,每次运行调用一次即可
(APK 在 `/data/app` 只读挂载,安装后不会变;**不需要**高频轮询)。
⚠️ 基线**不要**用"第一次运行时的指纹"——第一次可能已经是重打包版,那样等于把攻击者指纹当官方基线。

### Key Attestation 验证侧(第 8 项)

字段只是"数据",**验过才算证据**。验证侧补了三件事:逐级验签、根信任锚、challenge 回验。

```java
// ① 服务端下发一次性 nonce —— 这一步是防重放的关键:题目必须"别人出、别人验"
KeyAttestation.setChallenge(serverNonce);                             // 16~32 字节随机数
KeyAttestation.setTrustedRootsFromPem(GOOGLE_ATTESTATION_ROOT_PEM);   // 根信任锚(assets/服务端下发)
KeyAttestation.setVerifiedBootHashBaselineHex(officialBootHashHex);   // 可选:比启动链哈希基线

// ② 采集 + 本地自检(逐级验签 + 根信任锚 + challenge 回验)+ 回填 native
String err = KeyAttestation.collectAndPush();     // null = 成功

// ③ 上报整条链,服务端做权威判定(自己验链、自己比 nonce、自己比基线)
List<String> chainB64 = KeyAttestation.chainBase64();
```

回填字段 `att_chain_verified`:**1 = 自检通过 / 0 = 验证失败 / -1 = 未知**(没给 nonce 或缺根信任锚时不做自检)。
`0` 会直接判风险 —— 注意这是"字段看着已锁定、但链根本不可信"的场景,单看字段是发现不了的。

⚠️ **客户端自检能被 Frida hook 绕过**(把它改成恒返回 true 即可),所以:
- 自检的价值 = 挡掉"自己 openssl 签一张假链"这类低成本对抗 + 让 SDK 能自证;
- **权威判定必须在服务端**:nonce 由服务端生成(一次性、短期过期)、链由服务端验、
  基线由服务端持有、结论由服务端签发(这就是把红线画在哪的意义)。

PC 上不装 Android 也能验(纯 Java,拿真实证书跑):

```bash
javac -d out java/com/sec/detect/AttestationParser.java \
             java/com/sec/detect/KeyAttestationVerifier.java \
             java/com/sec/detect/KeyAttestationSelfTest.java
# 正/反两个方向都跑:正常链 → 验过;--tamper 改一字节 → 必被验签抓到
java -cp out com.sec.detect.KeyAttestationSelfTest cert0.der cert1.der cert2.der cert3.der \
     --root cert3.der --nonce <证书里的 challenge hex> [--tamper]
```

测试素材:Google 官方测试证书在 `google/android-key-attestation` 仓库的
`src/test/resources/der/`(chain 顺序就是 cert0→cert3,最后一张是自签根);
`tools/make_synthetic_attestation_chain.py` 可以合成一条"已锁定 + Verified"的链,
用来覆盖"全绿"分支;`tools/native_attest_smoke.cpp` 是不需要设备的 native 判定冒烟测试。

## 构建

需要 Android NDK(r29 验证):

```bash
NDK=/path/to/android-ndk-r29
cmake -S . -B build/arm64 \
      -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64 -j
```

ARM32 把 `-DANDROID_ABI=armeabi-v7a`、`-B build/v7a` 即可。加 `-DSEC_BUILD_JNI=OFF` 可只编纯 native 库。

产物:

- `libsecsdk.so` — SDK 本体(C ABI)
- `libsecsdk-jni.so` — JNI 版(入口 `JNI_OnLoad`,配 `java/` 下的辅助类使用;需 `libc++_shared.so`)
- `secdetect` — 命令行工具(单文件,可独立 push 运行)

## 使用

### 命令行验证

```bash
adb push build/arm64/secdetect /data/local/tmp/
adb shell chmod +x /data/local/tmp/secdetect
adb shell su -c /data/local/tmp/secdetect all
adb shell su -c /data/local/tmp/secdetect pid:1234   # 扫别的进程(需 root)
```

输出示例:

```
1|root|L3 prop[magisk]: ro.magisk.version=...; L7 boot chain: verifiedbootstate=orange
2|debugger|(clean)
3|frida|frida: [thread] gum-js-loop; frida: [scan] mem hit "frida:rpc" @0x7f... 
8|bootloader|vbstate: ro.boot.verifiedbootstate=orange
9|usb_debug|java: Settings.Global.ADB_ENABLED=1 (USB 调试已打开)
```

未命中标 `(clean)`,整体返回码取最严重项。

重打包检测(7)用法:

```bash
secdetect 7 /data/app/<pkg>/base.apk                          # 校准:打印 v1/v2/v3 证书指纹
secdetect 7 "/data/app/<pkg>/base.apk,<md5或sha256>[|<更多>]"  # 比对:不一致判风险
```

### App 集成(JNI + Java)

```
jni/sec_jni.cpp                    JNI 桥(注册 nativeDetect/nativeSetEnvFacts/nativeSetAttestation)
java/com/sec/detect/SecDetectBridge.java   Java 侧采集 USB/ADB/传感器/GL/包数/自身 APK 路径
java/com/sec/detect/KeyAttestation.java    Key Attestation 采集(KeyStore 生成带挑战的密钥 + 取证书链)
java/com/sec/detect/AttestationParser.java 纯 Java ASN.1 解析器(零 Android 依赖 → 可在 PC 上自测;
                                           challenge / verifiedBootHash 都带出来了)
java/com/sec/detect/KeyAttestationVerifier.java **验证侧**:逐级验签 + 根信任锚 + challenge 回验
                                           + 字段判定(纯 Java,服务端可复用同一套逻辑)
java/com/sec/detect/AttestationParserSelfTest.java  解析器自测(拿真实证书跑,开发期用)
java/com/sec/detect/KeyAttestationSelfTest.java      验证侧自测(正向 + --tamper 反向,开发期用)
java/com/sec/detect/SecDetectJava.java     门面:prepare() / scan() / checkRepack() / signatureMd5()
```

Attestation 解析器可以在 PC 上单独验证(不装 Android):

```bash
javac -d out java/com/sec/detect/AttestationParser.java java/com/sec/detect/AttestationParserSelfTest.java
java -cp out com.sec.detect.AttestationParserSelfTest my_attest_cert.der
```

```java
SecDetectBridge.officialSignatureBaseline = "ceda68c1...";   // CI 从发布包生成后固化,或服务端下发
SecDetectJava.prepare(getApplicationContext());              // 回填环境事实(含自身 APK 路径)
SecDetectJava.Result r = SecDetectJava.scan(ctx, null);      // 12 项全扫,不用传 apk 路径
if (r.risk) Log.w("SecDetect", r.output);
```

`checkRepack()` 可单独只跑重打包项(同样不用传路径)。

## 目录结构

```
include/sec_detect_api.h      公开接口:枚举、返回码、env facts、TEE 占位
src/api.cpp                   调度与参数校验(12 项注册表)
src/util.cpp                  /proc、maps、内存、线程、端口、属性、sysfs 取证原语
src/apk_signature.cpp         APK v1/v2/v3 签名解析 + 证书 MD5/SHA-256(MD5 自实现)
src/env_facts.cpp             环境事实回填区(Java/JNI -> native)
src/det_*.cpp                 12 项检测实现(每项一个文件)
src/tee_stub.cpp              TEE 后端占位
src/export.map                .dynsym 白名单(纯 native 版)
jni/sec_jni.cpp, jni/export_jni.map   JNI 桥与导出白名单
java/com/sec/detect/*.java    Java 辅助类
demo/main.cpp                 命令行 runner
tools/                        开发期测试:
                              make_synthetic_attestation_chain.py(合成"已锁定"测试链)
                              native_attest_smoke.cpp(第 8 项验证侧判定冒烟,不需要设备)
                              host_smoke.sh(宿主整库冒烟:参数校验/多路径/12 项跑通/自命中回归)
                              host-shim/(给宿主编译用的 sys/system_properties.h 桩)
docs/改动说明_v1.1.0.md        本次改动逐条说明与证据链
```

## 限制

- 全部为进程内用户态旁证;持 root 者可改名、改端口、内存加载绕过大部分单项(组合使用可提高成本)
- 反隐藏 root 依赖:属性枚举 + mount namespace 差分 + 启动链属性;`resetprop` 可清除属性,但差分与 TEE 证明不受影响
- 扫别的进程需 root/同 uid(App 沙盒被 SELinux 挡);产品形态是 SDK 集成进被保护 App 查自身
- 代码完整性只覆盖文件映射的 `x` 段;匿名/JIT 段要 opcode 扫描兜底(第 3 项已部分覆盖)
- 第 8 项第 2 层(TEE 字段)现在**带验证侧**:客户端可自检(逐级验签 + 根信任锚 + challenge 回验),
  结论以 `att_chain_verified` 回填(1/0/-1)。但**客户端自检可被 hook 绕过**,`verifiedBootHash`
  也必须有官方基线才能比对 —— 这两件事只能在服务端做权威判定
  (nonce 服务端下发、一次性、短期过期;链与基线都由服务端持有)
