/* sys/system_properties.h — 宿主(WSL/Linux)编译用的**桩头**
 *
 * 为什么需要:整个 SecDetectSDK 只有一处 Android 专有依赖 ——
 *   src/util.cpp 里的 #include <sys/system_properties.h> 与 __system_property_* 调用。
 * 其余全是 /proc、maps、端口、文件、内存的 Linux 通用取证。
 * 于是给宿主版编一份桩:属性读取返回"空/未命中"(属性相关的检测项在宿主上自然报 clean/unknown,
 * 这正是预期行为,不是 bug),就能在 WSL 里把**其余全部逻辑**(调度、参数校验、repack 多路径、
 * 检测项注册表…)真跑一遍 —— 推手机之前最划算的一次验证。
 *
 * 用法:
 *   g++ -std=c++17 -I tools/host-shim -Iinclude -Isrc src/*.cpp demo/main.cpp -o /tmp/secdetect_host
 *   /tmp/secdetect_host 7 "/path/a.apk|/path/b.apk"      # 多路径参数校验
 *   /tmp/secdetect_host all
 *
 * 注意:这份桩**只用于宿主冒烟**,绝不进 Android 产物(不在 CMakeLists 的 include 路径里)。
 */
#ifndef SECDETECT_HOST_SHIM_SYSTEM_PROPERTIES_H
#define SECDETECT_HOST_SHIM_SYSTEM_PROPERTIES_H

#include <cstdint>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

#define PROP_NAME_MAX  32
#define PROP_VALUE_MAX 92

/* 不透明类型:调用方只拿它的指针(Bionic 里也是这么用的) */
typedef struct prop_info prop_info;

/* 读单个属性;宿主上一律"不存在"(返回 0 且 value 置空) */
static inline int __system_property_get(const char* /*name*/, char* value) {
    if (value) value[0] = '\0';
    return 0;
}

/* API < 26 的读取路径(宿主没有 __ANDROID_API__ 宏,util.cpp 会走这条) */
static inline int __system_property_read(const prop_info* /*pi*/, char* name, char* value) {
    if (name) name[0] = '\0';
    if (value) value[0] = '\0';
    return -1;
}

/* API >= 26 的读取路径(留着保证两分支都能编过) */
static inline void __system_property_read_callback(
        const prop_info* /*pi*/,
        void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
        void* cookie) {
    if (callback) callback(cookie, "", "", 0);
}

/* 全量枚举:宿主上没有属性可枚举 */
static inline void __system_property_foreach(
        void (*callback)(const prop_info* pi, void* cookie), void* cookie) {
    (void)callback;
    (void)cookie;
}

#ifdef __cplusplus
}
#endif

#endif /* SECDETECT_HOST_SHIM_SYSTEM_PROPERTIES_H */
