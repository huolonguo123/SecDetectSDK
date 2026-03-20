/*
 * sec_detect_api.h — SecDetect SDK 对外统一接口(纯 C ABI,给 JNI / 上层调用)
 *
 * 设计约束(与设计文档一致):
 *   1. 函数内部绝不修改 input 指向的内存(input 只读);
 *   2. output 由调用方分配,SDK 只写不分配;
 *   3. output 长度超过 output_len 一律截断,绝不越界写;
 *   4. 返回码只有三个:-1 参数错误 / 0 未发现风险 / 1 检测到风险。
 */
#ifndef SEC_DETECT_API_H
#define SEC_DETECT_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SECDETECT_VERSION "1.0.0"

/* 导出符号可见性:配合 CMake 的 -fvisibility=hidden,
 * 只有标注 SEC_API 的符号进 .dynsym,减小导出面 */
#if defined(__GNUC__) || defined(__clang__)
#define SEC_API __attribute__((visibility("default")))
#else
#define SEC_API
#endif

/* ------------------------------------------------------------------ */
/* 检测项枚举(共 9 项;数字即 DETECT_xxx,稳定,别改,调用方可能持久化)  */
/* ------------------------------------------------------------------ */
typedef enum {
    DETECT_ROOT       = 1,  /* Root / Magisk 特征                               */
    DETECT_DEBUGGER   = 2,  /* 调试器附加(ptrace)+ IDA android_server / gdbserver */
    DETECT_FRIDA      = 3,  /* Frida 注入 / frida-server 驻留                    */
    DETECT_XPOSED     = 4,  /* Xposed / LSPosed / Riru / Zygisk 模块             */
    DETECT_EMULATOR   = 5,  /* QEMU 类模拟器                                     */
    DETECT_VM         = 6,  /* 虚拟机 / 双开容器(非 QEMU 形态)                   */
    DETECT_REPACK     = 7,  /* 重打包破解:APK 签名指纹比对(需 input 传 APK)      */
    DETECT_BOOTLOADER = 8,  /* Bootloader 解锁                                    */
    DETECT_USB_DEBUG  = 9,  /* USB 调试开关 / 网络 adb                            */
    DETECT_MODULE     = 10, /* 非白名单可执行模块(进程内 maps 白名单差分)        */
    DETECT_ALL        = 0x7F /* 全套扫描(忽略 input)                             */
} sec_detect_type_t;

/* 返回码 */
#define SEC_ERR_PARAM (-1)  /* 参数错误:非法枚举 / output 与 len 不匹配 /
                                repack 缺 input 或 APK 打不开                  */
#define SEC_OK        (0)   /* 该项未发现风险 */
#define SEC_RISK      (1)   /* 该项检测到风险,原因写入 output */

/* ------------------------------------------------------------------ */
/* 统一检测入口                                                         */
/*                                                                      */
/* 参数:                                                                */
/*   detect_type : 检测项枚举,DETECT_ALL 时对 9 项全扫(只保留最后一项    */
/*                 的 output?不——全扫时 output 写"分号分隔的汇总",见下) */
/*   input       : 只读输入,可为 NULL。仅 DETECT_REPACK 必填:           */
/*                   input = "/data/app/.../base.apk"            校准模式  */
/*                   input = "/data/app/.../base.apk,SHA256hex"  比对模式  */
/*                 其余检测项传 NULL 即可。DETECT_ALL 时可传 APK 路径    */
/*                 让 repack 也参与(否则该行输出 skipped)。              */
/*   output      : 调用方分配的输出缓冲,SDK 只写不分配。可传 NULL(此时  */
/*                 output_len 必须为 0,等价于"只取返回码")。              */
/*   output_len  : output 容量(字节)。原因文本超过容量会被截断并加 '~' 尾。*/
/*                                                                      */
/* 返回:                                                                */
/*   SEC_ERR_PARAM / SEC_OK / SEC_RISK                                   */
/*   检测到风险时,output 里是证据串,形如:                                */
/*     "root: /system/xbin/su exists; magiskd: init.svc.magiskd=running" */
/*   DETECT_ALL 全扫时:每项占一行,行首是 "编号|名字|",名字即检测项      */
/*   (root/debugger/frida/...),未命中标 (clean),例如:                     */
/*     1|root|magisk data: /data/adb/magisk                                */
/*     2|debugger|(clean)                                                  */
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
/* ------------------------------------------------------------------ */
typedef int (*tee_attest_fn)(char* out, size_t out_len);
SEC_API void secdetect_tee_set_backend(tee_attest_fn fn);
SEC_API int  secdetect_tee_attest(char* output, size_t output_len); /* 未集成返回 1 */

#ifdef __cplusplus
}
#endif

#endif /* SEC_DETECT_API_H */
