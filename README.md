# SecDetectSDK

Android 客户端安全检测 SDK(C/C++)。在 App 进程内做 10 项风险检测:Root、调试器、Frida、Xposed、模拟器、虚拟机/双开、重打包、Bootloader 解锁、USB 调试、非白名单模块注入。

对外暴露纯 C ABI,单函数入口,可集成进 Android App,也可用附带的命令行工具单独运行。

## 检测项

| # | 检测 | 说明 |
|---|------|------|
| 1 | Root / Magisk | su 路径、boot 修补载荷、Magisk 数据目录 |
| 2 | 调试器 / IDA | ptrace 附加状态(TracerPid)、android_server/gdbserver |
| 3 | Frida | 注入模块映射、frida-server 进程与端口 |
| 4 | Xposed / LSPosed | 框架注入痕迹(Riru/Zygisk/EdXp) |
| 5 | 模拟器 | QEMU 硬件特征(goldfish 等) |
| 6 | 虚拟机 / 双开 | VM 平台属性、双开容器映射 |
| 7 | 重打包 | APK v1 签名指纹比对(内置 ZIP 解析) |
| 8 | Bootloader | AVB 状态属性(verifiedbootstate 等) |
| 9 | USB 调试 | usb config / adb 使能状态 |
| 10 | 模块注入 | 可执行模块白名单差分(非系统/非自身 so) |

所有检测为用户态旁证,单项均可被针对性绕过,适合组合使用。

## 接口

```c
int secdetect(int detect_type, const char* input, char* output, size_t output_len);
```

- `detect_type`:检测项编号 1-10,`DETECT_ALL(0x7F)` 全扫
- `input`:只读入参;仅重打包检测(7)需要,传 APK 路径,其余传 NULL
- `output`:调用方分配的缓冲区,SDK 只写不分配
- `output_len`:缓冲区长度,超长自动截断

返回码:`-1` 参数错误 / `0` 未发现风险 / `1` 检测到风险。命中时 `output` 携带证据文本。

TEE 扩展:`secdetect_tee_set_backend()` 可注入厂商 TA 后端,未注入时 `secdetect_tee_attest()` 明确返回未集成。

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

ARM32 将 `-DANDROID_ABI=armeabi-v7a`、`-B build/v7a` 即可。

产物:

- `libsecsdk.so` — SDK 本体,放入 App 的 `jniLibs/<abi>/` 集成
- `secdetect` — 命令行工具,用于验证(单文件,可独立 push 运行)

## 使用

### 命令行验证

```bash
adb push build/arm64/secdetect /data/local/tmp/
adb shell chmod +x /data/local/tmp/secdetect
adb shell su -c /data/local/tmp/secdetect all
```

输出示例:

```
1|root|magisk data: /data/adb/magisk
2|debugger|(clean)
3|frida|(clean)
8|bootloader|vbstate: ro.boot.verifiedbootstate=orange
9|usb_debug|usb: persist.sys.usb.config=adb (adb enabled)
```

未命中的项标 `(clean)`,整体返回码取最严重项。

单项检测:

```bash
adb shell su -c /data/local/tmp/secdetect root     # 只查 Root
adb shell su -c /data/local/tmp/secdetect 2        # 只查调试器
adb shell su -c /data/local/tmp/secdetect 7 /data/app/<pkg>/base.apk   # 重打包
```

重打包检测(7)两种用法:只传 APK 路径 = 校准模式,打印当前指纹;传 `路径,<基线sha256>` = 比对模式,指纹不一致判为风险。

### App 集成

```java
System.loadLibrary("secsdk");   // 注意同时打包 libc++_shared.so
```

```c
char out[512];
int r = secdetect(SEC_DETECT_ROOT | SEC_DETECT_FRIDA, NULL, out, sizeof out);
```

## 目录结构

```
include/sec_detect_api.h   公开接口:枚举、返回码、函数声明
src/det_*.cpp              9 项检测实现(每个一项)
src/tee_stub.cpp           TEE 后端占位
src/api.cpp                调度与参数校验
demo/main.cpp              命令行工具入口
```

## 限制

- 全部检测为进程内用户态旁证,无 TEE 强校验;对抗者持 root 后可改名、改端口、内存加载绕过大部分单项
- 重打包检测仅覆盖 v1 签名;v2/v3-only 的 APK 建议改用 Java 层 `PackageManager` 取签名证书 digest 做基线
- 只能发现注入自身进程的模块
