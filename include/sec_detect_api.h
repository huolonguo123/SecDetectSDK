/*
 * sec_detect_api.h — SecDetect SDK 对外统一接口(纯 C ABI,给 JNI / 上层调用)
 *
 * 设计约束(与设计文档一致):
 *   1. 函数内部绝不修改 input 指向的内存(input 只读);
 *   2. output 由调用方分配,SDK 只写不分配;
 *   3. output 长度超过 output_len 一律截断,绝不越界写;
 *   4. 返回码只有三个:-1 参数错误 / 0 未发现风险 / 1 检测到风险。
 *
 * v1.1.0 新增:
 *   - 第 11 项「代码完整性校验」(内存 vs 磁盘同偏移逐字节比对)
 *   - 第 12 项「IDA 调试服务专项」(与 frida 分开,各自独立检测项)
 *   - sec_env_facts_t + secdetect_set_env_facts():Java/JNI 侧把
 *     "只有 Java 才能拿到的环境事实"(USB 连接、adb_enabled、
 *     传感器数量、GL_RENDERER、Key Attestation 结果)回填给 native 检测项
 */
#ifndef SEC_DETECT_API_H
#define SEC_DETECT_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECDETECT_VERSION "1.1.0"

/* 导出符号可见性:配合 CMake 的 -fvisibility=hidden,
 * 只有标注 SEC_API 的符号进 .dynsym,减小导出面 */
#if defined(__GNUC__) || defined(__clang__)
#define SEC_API __attribute__((visibility("default")))
#else
#define SEC_API
#endif

/* ------------------------------------------------------------------ */
/* 检测项枚举(共 12 项;数字即 DETECT_xxx,稳定,别改,调用方可能持久化)  */
/* ------------------------------------------------------------------ */
typedef enum {
    DETECT_ROOT       = 1,  /* Root / Magisk 特征(含反隐藏:属性枚举/命名空间差分) */
    DETECT_DEBUGGER   = 2,  /* 调试器附加(ptrace)+ gdb/lldb/jdb 等全量进程名单       */
    DETECT_FRIDA      = 3,  /* Frida 注入 / frida-server 驻留 / 魔改版特征            */
    DETECT_XPOSED     = 4,  /* Xposed / LSPosed / Riru / Zygisk 模块                 */
    DETECT_EMULATOR   = 5,  /* QEMU / PC 模拟器(houdini 转译、厂商特征、GPU 等)       */
    DETECT_VM         = 6,  /* 虚拟机 / 双开多开(同进程多应用)                        */
    DETECT_REPACK     = 7,  /* 重打包破解:v1/v2/v3 签名指纹比对(需 input 传 APK)     */
    DETECT_BOOTLOADER = 8,  /* Bootloader 解锁 + Google Key Attestation(TEE)          */
    DETECT_USB_DEBUG  = 9,  /* USB 调试 / 开发选项 / 物理 USB 连接                    */
    DETECT_MODULE     = 10, /* 非白名单可执行模块(进程内 maps 白名单差分)            */
    DETECT_INTEGRITY  = 11, /* 代码完整性:内存映射 vs 磁盘文件逐字节比对             */
    DETECT_IDA        = 12, /* IDA Pro android_server / dbgsrv 服务专项              */
    DETECT_ALL        = 0x7F /* 全套扫描(忽略 input)                                 */
} sec_detect_type_t;

/* 返回码 */
#define SEC_ERR_PARAM (-1)  /* 参数错误:非法枚举 / output 与 len 不匹配 /
                                repack 缺 input 或 APK 打不开                  */
#define SEC_OK        (0)   /* 该项未发现风险 */
#define SEC_RISK      (1)   /* 该项检测到风险,原因写入 output */

/* ------------------------------------------------------------------ */
/* 环境事实回填(Java/JNI -> native)                                    */
/*                                                                      */
/* 有些事实只有 Java 层拿得到(UsbManager、Settings.Global、SensorManager、   */
/* GL_RENDERER、KeyStore Key Attestation)。SDK 提供这个 C ABI 结构,        */
/* 由 JNI 桥(jni/sec_jni.cpp)或调用方直接填好后再调 secdetect():          */
/*                                                                      */
/*   sec_env_facts_t f = {0};                                            */
/*   f.provided = SEC_FACT_ADB_ENABLED | SEC_FACT_USB_CONNECTED;         */
/*   f.adb_enabled = 1; f.usb_connected = 1;                             */
/*   secdetect_set_env_facts(&f);    // 之后 usb_debug/bootloader 项生效  */
/*                                                                      */
/* 约定:整数值 -1 = 未知(检测项会跳过该条证据,不会误报);                    */
/*       provided 位图之外/未知字段一律忽略。                              */
/* ------------------------------------------------------------------ */

#define SEC_FACT_USB_CONNECTED   (1u << 0)  /* usb_connected     */
#define SEC_FACT_ADB_ENABLED     (1u << 1)  /* adb_enabled       */
#define SEC_FACT_DEV_OPTIONS     (1u << 2)  /* dev_options       */
#define SEC_FACT_MOCK_LOCATION   (1u << 3)  /* mock_location     */
#define SEC_FACT_PKG_COUNT       (1u << 4)  /* pkg_count_for_uid */
#define SEC_FACT_SENSOR_COUNT    (1u << 5)  /* sensor_count      */
#define SEC_FACT_BLUETOOTH       (1u << 6)  /* bluetooth         */
#define SEC_FACT_GL_RENDERER     (1u << 7)  /* gl_renderer[]     */
#define SEC_FACT_HW_KEY          (1u << 8)  /* hw_backed_key     */
#define SEC_FACT_ATTESTATION     (1u << 9)  /* att_* 一整套       */
#define SEC_FACT_APK_PATH        (1u << 10) /* apk_path[]        */
#define SEC_FACT_APK_BASELINE    (1u << 11) /* apk_baseline[]    */

#define SEC_ENV_STR_MAX 64
#define SEC_ENV_SEC_LEVEL_MAX 24
#define SEC_ENV_PATH_MAX 192        /* 自身 APK 路径;多 split 用 '|' 分隔 */
#define SEC_ENV_BASELINE_MAX 128    /* 官方签名指纹基线;多基线用 '|' 分隔 */

typedef struct sec_env_facts {
    uint32_t provided;            /* SEC_FACT_* 位图:置位的字段才有效 */

    int32_t  usb_connected;       /* USB 是否物理连接(数据线/充电) 1/0/-1 */
    int32_t  adb_enabled;         /* Settings.Global.ADB_ENABLED             */
    int32_t  dev_options;         /* Settings.Global.DEVELOPMENT_SETTINGS_ENABLED */
    int32_t  mock_location;       /* Settings.Secure 允许模拟位置            */
    int32_t  pkg_count_for_uid;   /* 本 uid 下的包数量(>1 = 双开/多开)       */
    int32_t  sensor_count;        /* SensorManager 传感器数量(0 = 强信号)     */
    int32_t  bluetooth;           /* 蓝牙是否可用 1/0                         */
    int32_t  hw_backed_key;       /* 生成密钥是否硬件(TEE)支持 1/0            */
    int32_t  att_verified_boot_state; /* 0 green 1 yellow 2 orange 3 red -1 未知 */
    int32_t  att_device_locked;   /* 1 已锁 0 已解锁 -1 未知                  */
    int32_t  att_verified_boot_hash_ok; /* 1 = 启动链哈希与证书一致          */
    int32_t  att_sw_enforced;     /* 1 = 仅软件强制(root/模拟器可伪造)        */
    int32_t  att_chain_verified;  /* 客户端自检的**证书链验证结论**:
                                   *   1 = 逐级验签 + 根信任锚 + challenge 回验 均通过
                                   *   0 = 验证失败(伪造/重放/根不对 → 强信号)
                                   *  -1 = 未知(未做自检:缺 nonce 或缺根信任锚)
                                   * ★ 客户端自检可被 hook 绕过,权威判定在服务端。 */
    char     gl_renderer[SEC_ENV_STR_MAX];      /* GL_RENDERER(e.g. SwiftShader) */
    char     att_os_version[SEC_ENV_STR_MAX];   /* "Android 13 patch 2024-01"     */
    char     att_security_level[SEC_ENV_SEC_LEVEL_MAX]; /* "TEE"/"StrongBox"/"Software" */
    /* --- 重打包检测(第 7 项)的免传参通道 ---
     * Java:context.getApplicationInfo().sourceDir(+ splitSourceDirs 用 '|' 拼)
     * native 拿不到可靠路径(/proc/self/exe 是 app_process;/data/app 0711 列不了目录),
     * 所以由 Java 回填,repack 项在没有 input 时自动用它。 */
    char     apk_path[SEC_ENV_PATH_MAX];
    /* 官方签名指纹基线:32 位 MD5 或 64 位 SHA-256(小写);多基线用 '|' 分隔。
     * **不要**用"第一次运行时的指纹"当基线——第一次可能已经是重打包版;
     * 基线应由 CI 从发布包生成后固化,或服务端下发。 */
    char     apk_baseline[SEC_ENV_BASELINE_MAX];
    int32_t  reserved[1];         /* 预留(reserved[2] 的一格已改名为 att_chain_verified) */
} sec_env_facts_t;

/* 回填/覆盖环境事实(SDK 内部拷贝一份,调用方栈上的结构可随即释放) */
SEC_API void secdetect_set_env_facts(const sec_env_facts_t* facts);

/* 读出当前生效的环境事实(拷贝语义;未设置的字段为 0 且 provided 未置位) */
SEC_API void secdetect_get_env_facts(sec_env_facts_t* out);

/* ------------------------------------------------------------------ */
/* 统一检测入口                                                         */
/*                                                                      */
/* 参数:                                                                */
/*   detect_type : 检测项枚举,DETECT_ALL 时对 12 项全扫                  */
/*   input       : 只读输入,可为 NULL。重打包(7)有两种给路径的方式:      */
/*                   a) input = "/data/app/.../base.apk[,<基线>]"            */
/*                      (基线可为 md5/sha256,多基线用 '|')                   */
/*                   b) **不回传 input**,改由 Java 用                     */
/*                      SEC_FACT_APK_PATH / SEC_FACT_APK_BASELINE 回填      */
/*                      (App 集成形态:省掉每次传 apk 路径)                    */
/*                 可扫其它进程的项(root/同 uid):input = "pid:<pid>"        */
/*                 其余检测项传 NULL 即可。DETECT_ALL 时 input 会传给每一项(  */
/*                 pid-based 项会解析 "pid:N";repack 会当 apk 路径解析)      */
/*   output      : 调用方分配的输出缓冲,SDK 只写不分配。可传 NULL(此时  */
/*                 output_len 必须为 0,等价于"只取返回码")。              */
/*   output_len  : output 容量(字节)。原因文本超过容量会被截断并加 '~' 尾。*/
/*                                                                      */
/* 返回:                                                                */
/*   SEC_ERR_PARAM / SEC_OK / SEC_RISK                                   */
/*   DETECT_ALL 全扫时:每项占一行,行首是 "编号|名字|",未命中标 (clean)    */
/*     1|root|magisk data: /data/adb/magisk                              */
/*     2|debugger|(clean)                                                */
/* ------------------------------------------------------------------ */
SEC_API int secdetect(int detect_type, const char* input, char* output, size_t output_len);

/* 版本号,放进 output(最多 output_len 字节,含 '\0') */
SEC_API void secdetect_version(char* output, size_t output_len);

/* ------------------------------------------------------------------ */
/* TEE 扩展(占位)。设计文档要求:bootloader 状态、磁盘 ELF 基线哈希、     */
/* opcode 摘要这些"会被注入篡改的敏感判定"最终应放到 TEE 安全世界,       */
/* 普通侧只封装 TA 调用。本 SDK 用户态部分先落地,这里暴露后端抽象:       */
/*   返回 0  = 后端可用且返回了数据(真实产品:厂商 TA);                  */
/*   返回 1  = 当前环境无 TA / 未集成(本开源骨架的默认态,不视为风险)。   */
/* 集成方通过 secdetect_tee_set_backend 注入自己的 TA 通道实现。          */
/*                                                                      */
/* 另一条更现实的路径(google-attest):用 Android KeyStore 的 Key        */
/* Attestation 拿 TEE 签名的 attested key,解析 attestation 扩展里的     */
/* verified boot state / deviceLocked,再把结果通过                     */
/* secdetect_set_env_facts() 回填(见 java/.../KeyAttestation.java)。    */
/* ------------------------------------------------------------------ */
typedef int (*tee_attest_fn)(char* out, size_t out_len);
SEC_API void secdetect_tee_set_backend(tee_attest_fn fn);
SEC_API int  secdetect_tee_attest(char* output, size_t output_len); /* 未集成返回 1 */

#ifdef __cplusplus
}
#endif

#endif /* SEC_DETECT_API_H */
