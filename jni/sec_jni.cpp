/*
 * sec_jni.cpp — JNI 桥:Java 侧 <-> native 检测 SDK
 *
 * 三种能力:
 *   1) 调用检测:Java 直接要一个检测项的结果(nativeDetect)  —— 示例见 SecDetectBridge.java
 *   2) 回填环境事实:把只有 Java 才能拿到的东西(Settings.Global.ADB_ENABLED、
 *      UsbManager 连接状态、传感器数量、GL_RENDERER、Key Attestation 结果)
 *      填成 sec_env_facts_t 交给 secdetect_set_env_facts();
 *   3) 版本/后端信息。
 *
 * 设计要点:
 *   - 本文件属于 SDK 的"集成层",编译进 libsecsdk-jni.so(jni/export_jni.map);
 *     纯 native 集成(不装 Java)只用 libsecsdk.so 即可,两者共用同一套检测实现。
 *   - 所有 Java 方法名/签名集中在本文件注册(JNI_OnLoad + RegisterNatives),
 *     改名字只改一处;Java 侧见 java/com/sec/detect/SecDetectBridge.java。
 *   - 注意 USB 调试开关**必须**由 Java 读(见 SecDetectBridge.readAdbEnabled),
 *     native 只能读 sysfs 的"物理连接"。
 */
#include <jni.h>

#include <android/log.h>
#include <cstring>
#include <string>
#include <vector>

#include "sec_detect_api.h"

#define LOG_TAG "SecDetectJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

const char* kBridgeClass = "com/sec/detect/SecDetectBridge";

/* 返回 buffer 大小:证据串最长 2047 + 行头,4KB 足够 */
constexpr size_t kOutCap = 4096;

/* ---------------- 1) 检测调用 ----------------
 * Java: String nativeDetect(int type, String input)
 * 返回格式:"<code>\n<evidence>"(code = -1/0/1),方便 Java 直接拆。 */
jstring native_detect(JNIEnv* env, jclass, jint type, jstring jinput) {
    const char* input = nullptr;
    if (jinput) input = env->GetStringUTFChars(jinput, nullptr);

    std::vector<char> out(kOutCap, 0);
    int rc = secdetect((int)type, input, out.data(), out.size() - 1);

    if (input) env->ReleaseStringUTFChars(jinput, input);

    std::string res = std::to_string(rc) + "\n" + out.data();
    return env->NewStringUTF(res.c_str());
}

/* ---------------- 2) 环境事实回填 ----------------
 * Java: void nativeSetEnvFacts(int[] ints, String[] strs)
 *   ints[0..7] = usb_connected, adb_enabled, dev_options, mock_location,
 *                pkg_count_for_uid, sensor_count, bluetooth, hw_backed_key
 *   strs[0]    = gl_renderer
 *   strs[1]    = apk_path(自身 APK 路径;多 split 用 '|' 分隔)—— 可选
 *   strs[2]    = apk_baseline(官方签名指纹;多基线用 '|' 分隔)—— 可选
 * 只要 ints.length >= 1 就认为 Java 提供了一组事实(provided 按长度置位)。
 */
void native_set_env_facts(JNIEnv* env, jclass, jintArray jints, jobjectArray jstrs) {
    sec_env_facts_t ef;
    memset(&ef, 0, sizeof ef);
    ef.usb_connected = ef.adb_enabled = ef.dev_options = ef.mock_location = -1;
    ef.pkg_count_for_uid = ef.sensor_count = ef.bluetooth = ef.hw_backed_key = -1;

    if (jints) {
        jsize n = env->GetArrayLength(jints);
        jint* v = env->GetIntArrayElements(jints, nullptr);
        if (v) {
            if (n > 0) { ef.usb_connected = v[0]; ef.provided |= SEC_FACT_USB_CONNECTED; }
            if (n > 1) { ef.adb_enabled = v[1];   ef.provided |= SEC_FACT_ADB_ENABLED; }
            if (n > 2) { ef.dev_options = v[2];   ef.provided |= SEC_FACT_DEV_OPTIONS; }
            if (n > 3) { ef.mock_location = v[3]; ef.provided |= SEC_FACT_MOCK_LOCATION; }
            if (n > 4) { ef.pkg_count_for_uid = v[4]; ef.provided |= SEC_FACT_PKG_COUNT; }
            if (n > 5) { ef.sensor_count = v[5];  ef.provided |= SEC_FACT_SENSOR_COUNT; }
            if (n > 6) { ef.bluetooth = v[6];     ef.provided |= SEC_FACT_BLUETOOTH; }
            if (n > 7) { ef.hw_backed_key = v[7]; ef.provided |= SEC_FACT_HW_KEY; }
            env->ReleaseIntArrayElements(jints, v, JNI_ABORT);
        }
    }
    if (jstrs && env->GetArrayLength(jstrs) > 0) {
        /* 取第 i 个字符串填进 dst(带 provided 位) */
        auto put = [&](int idx, char* dst, size_t cap, uint32_t bit) {
            if (env->GetArrayLength(jstrs) <= idx) return;
            jstring js = (jstring)env->GetObjectArrayElement(jstrs, idx);
            if (!js) return;
            const char* s = env->GetStringUTFChars(js, nullptr);
            if (s) {
                snprintf(dst, cap, "%s", s);
                if (*dst) ef.provided |= bit;
                env->ReleaseStringUTFChars(js, s);
            }
            env->DeleteLocalRef(js);
        };
        put(0, ef.gl_renderer, sizeof ef.gl_renderer, SEC_FACT_GL_RENDERER);
        put(1, ef.apk_path, sizeof ef.apk_path, SEC_FACT_APK_PATH);
        put(2, ef.apk_baseline, sizeof ef.apk_baseline, SEC_FACT_APK_BASELINE);
    }
    secdetect_set_env_facts(&ef);
}

/* ---------------- 3) Key Attestation 结果回填 ----------------
 * Java: void nativeSetAttestation(int[] ints, String[] strs)
 *   ints[0..4] = verified_boot_state(0..3), device_locked(0/1),
 *                verified_boot_hash_ok(0/1), sw_enforced(0/1),
 *                chain_verified(1 通过 / 0 失败 / -1 未知 —— 客户端自检的链验证结论)
 *   strs[0]=os_version, strs[1]=security_level
 */
void native_set_attestation(JNIEnv* env, jclass, jintArray jints, jobjectArray jstrs) {
    /* 先读出当前 facts,只覆盖 attestation 部分,避免把别的事实冲掉 */
    sec_env_facts_t ef;
    secdetect_get_env_facts(&ef);

    if (jints) {
        jsize n = env->GetArrayLength(jints);
        jint* v = env->GetIntArrayElements(jints, nullptr);
        if (v) {
            if (n > 0) ef.att_verified_boot_state = v[0];
            if (n > 1) ef.att_device_locked = v[1];
            if (n > 2) ef.att_verified_boot_hash_ok = v[2];
            if (n > 3) ef.att_sw_enforced = v[3];
            if (n > 4) ef.att_chain_verified = v[4];   /* 验证侧:自检结论 */
            env->ReleaseIntArrayElements(jints, v, JNI_ABORT);
        }
    }
    if (jstrs) {
        jsize n = env->GetArrayLength(jstrs);
        if (n > 0) {
            jstring js = (jstring)env->GetObjectArrayElement(jstrs, 0);
            if (js) {
                const char* s = env->GetStringUTFChars(js, nullptr);
                if (s) {
                    snprintf(ef.att_os_version, sizeof ef.att_os_version, "%s", s);
                    env->ReleaseStringUTFChars(js, s);
                }
                env->DeleteLocalRef(js);
            }
        }
        if (n > 1) {
            jstring js = (jstring)env->GetObjectArrayElement(jstrs, 1);
            if (js) {
                const char* s = env->GetStringUTFChars(js, nullptr);
                if (s) {
                    snprintf(ef.att_security_level, sizeof ef.att_security_level, "%s", s);
                    env->ReleaseStringUTFChars(js, s);
                }
                env->DeleteLocalRef(js);
            }
        }
    }
    ef.provided |= SEC_FACT_ATTESTATION;
    secdetect_set_env_facts(&ef);
}

/* ---------------- 4) 版本 ----------------
 * Java: String nativeVersion() */
jstring native_version(JNIEnv* env, jclass) {
    char buf[32] = {0};
    secdetect_version(buf, sizeof buf);
    return env->NewStringUTF(buf);
}

/* 注册表:Java 方法名 -> native 函数 */
const JNINativeMethod kMethods[] = {
    {"nativeDetect",        "(ILjava/lang/String;)Ljava/lang/String;", (void*)native_detect},
    {"nativeSetEnvFacts",   "([I[Ljava/lang/String;)V",                (void*)native_set_env_facts},
    {"nativeSetAttestation","([I[Ljava/lang/String;)V",                (void*)native_set_attestation},
    {"nativeVersion",       "()Ljava/lang/String;",                    (void*)native_version},
};

}  // namespace

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }
    jclass cls = env->FindClass(kBridgeClass);
    if (!cls) {
        LOGE("JNI_OnLoad: class %s not found (check package name)", kBridgeClass);
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, kMethods,
                             (jint)(sizeof kMethods / sizeof kMethods[0])) != JNI_OK) {
        LOGE("JNI_OnLoad: RegisterNatives failed");
        return JNI_ERR;
    }
    char ver[32] = {0};
    secdetect_version(ver, sizeof ver);
    LOGI("SecDetect JNI loaded (SDK %s)", ver);
    return JNI_VERSION_1_6;
}
