/* SecDetectBridge.java — SecDetect SDK 的 Java 侧桥接(示例实现)
 *
 * 位置:java/com/sec/detect/SecDetectBridge.java
 * 依赖:libsecsdk-jni.so(jni/sec_jni.cpp 编出来的 JNI 版本)
 *
 * 分工(重要,面试常问):
 *   - native(libsecsdk.so)能干:进程/内存/文件/端口/属性/映射 —— 即
 *     "进程自省"这一层。
 *   - **只有 Java 能干**:
 *       * USB 调试开关        → Settings.Global.ADB_ENABLED
 *       * 开发者选项开关      → Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
 *       * 模拟位置            → Settings.Secure.ALLOW_MOCK_LOCATION
 *       * 物理 USB 连接       → UsbManager / ACTION_BATTERY_CHANGED
 *       * 传感器数量          → SensorManager(模拟器 = 0)
 *       * GL_RENDERER         → EGL/GLES(SwiftShader = 模拟器)
 *       * 同 uid 的包数量     → PackageManager.getPackagesForUid (双开/多开)
 *       * 签名证书指纹        → PackageInfo.signingInfo(重打包)
 *       * Key Attestation     → KeyStore(TEE 签名,见 KeyAttestation.java)
 *     这些值通过 nativeSetEnvFacts()/nativeSetAttestation() 回填给 native
 *     检测项,而不是让 native 去瞎猜。
 *
 * 用法:
 *     SecDetectBridge.collectAndPush(context);        // 先回填环境事实
 *     String r = SecDetectBridge.detect(SecDetectBridge.DETECT_USB_DEBUG, null);
 *     KeyAttestation.collectAndPush();                // TEE 证明(可选,较慢)
 */
package com.sec.detect;

import android.app.ActivityManager;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.usb.UsbManager;
import android.opengl.GLES20;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Process;
import android.provider.Settings;

/** 与 include/sec_detect_api.h 的枚举保持一致的常量 */
public final class SecDetectBridge {

    /* ---- 检测项编号(与 C 枚举 sec_detect_type_t 一致,别改) ---- */
    public static final int DETECT_ROOT       = 1;
    public static final int DETECT_DEBUGGER   = 2;
    public static final int DETECT_FRIDA      = 3;
    public static final int DETECT_XPOSED     = 4;
    public static final int DETECT_EMULATOR   = 5;
    public static final int DETECT_VM         = 6;
    public static final int DETECT_REPACK     = 7;
    public static final int DETECT_BOOTLOADER = 8;
    public static final int DETECT_USB_DEBUG  = 9;
    public static final int DETECT_MODULE     = 10;
    public static final int DETECT_INTEGRITY  = 11;
    public static final int DETECT_IDA        = 12;
    public static final int DETECT_ALL        = 0x7F;

    /* ---- env facts 位图(与 SEC_FACT_* 一致) ---- */
    public static final int FACT_USB_CONNECTED = 1 << 0;
    public static final int FACT_ADB_ENABLED   = 1 << 1;
    public static final int FACT_DEV_OPTIONS   = 1 << 2;
    public static final int FACT_MOCK_LOCATION = 1 << 3;
    public static final int FACT_PKG_COUNT     = 1 << 4;
    public static final int FACT_SENSOR_COUNT  = 1 << 5;
    public static final int FACT_BLUETOOTH     = 1 << 6;
    public static final int FACT_GL_RENDERER   = 1 << 7;
    public static final int FACT_HW_KEY        = 1 << 8;
    public static final int FACT_ATTESTATION   = 1 << 9;

    static {
        System.loadLibrary("secsdk-jni");
    }

    private SecDetectBridge() {}

    /* ================= native 方法(jni/sec_jni.cpp 注册) ================= */

    /** 跑一个检测项,返回 "<code>\n<evidence>"(code: -1 参数错/0 干净/1 命中) */
    private static native String nativeDetect(int type, String input);

    /** 回填环境事实:ints = [usb, adb, devOptions, mockLocation, pkgCount, sensors, bt, hwKey],
     *  strs = [glRenderer, apkPath, apkBaseline](后两个可空串) */
    public static native void nativeSetEnvFacts(int[] ints, String[] strs);

    /** 回填 Key Attestation:ints = [vbs, locked, hashOk, swEnforced, chainVerified],
     *  strs = [osVersion, securityLevel]。
     *  chainVerified = 客户端自检结论(1 通过 / 0 失败 / -1 未知;见 KeyAttestation.collectAndPush)。
     *  ★ 客户端自检能被 hook 绕过 → 权威判定仍应在服务端(见 KeyAttestationVerifier 头注释)。 */
    public static native void nativeSetAttestation(int[] ints, String[] strs);

    public static native String nativeVersion();

    /* ================= Java 侧封装 ================= */

    public static final class Result {
        public final int code;         // -1 / 0 / 1
        public final String evidence;  // 证据串
        public Result(int code, String evidence) { this.code = code; this.evidence = evidence; }
        public boolean risk() { return code == 1; }
        @Override public String toString() {
            return "code=" + code + " evidence=" + evidence;
        }
    }

    /** 单测一个检测项;input 可为 null,或 "pid:<pid>" / repack 的 apk 路径 */
    public static Result detect(int type, String input) {
        String raw = nativeDetect(type, input);
        int nl = raw.indexOf('\n');
        if (nl < 0) return new Result(-1, raw);
        int code;
        try { code = Integer.parseInt(raw.substring(0, nl)); } catch (NumberFormatException e) { code = -1; }
        return new Result(code, raw.substring(nl + 1));
    }

    /** 全项扫描(需要 repack 的话 input 传 apk 路径) */
    public static Result detectAll(String input) { return detect(DETECT_ALL, input); }

    /* -------- 采集"只有 Java 能拿到"的事实,回填 native -------- */

    /** 官方签名指纹基线(32 位 MD5 或 64 位 SHA-256,小写;多基线用 '|')。
     *  ★ 必须由**构建期固化**或服务端下发,不要在运行时"第一次跑就记住" ——
     *    第一次的包可能已经是重打包版,那样等于把攻击者指纹当官方基线。 */
    public static volatile String officialSignatureBaseline = "";

    /** 采样并回填(建议在 Application.onCreate 或检测前调用一次) */
    public static void collectAndPush(Context ctx) {
        int usb = readUsbConnected(ctx);
        int adb = readAdbEnabled(ctx);
        int dev = readDevelopmentSettings(ctx);
        int mock = readMockLocation(ctx);
        int pkgCount = readPackagesForUidCount(ctx);
        int sensors = readSensorCount(ctx);
        int bt = readBluetoothAvailable();
        int hwKey = KeyAttestation.probeHardwareKey();
        String gl = readGlRenderer();
        String apkPath = readApkPaths(ctx);          // 自身 APK(+split),供 repack 免传路径

        nativeSetEnvFacts(
                new int[]{usb, adb, dev, mock, pkgCount, sensors, bt, hwKey},
                new String[]{gl == null ? "" : gl, apkPath, officialSignatureBaseline});
    }

    /** 自身 APK 路径:base + 所有 split,用 '|' 分隔(split 也是独立签名的文件)。
     *  native 拿不到这个路径(/proc/self/exe 是 app_process;/data/app 是 0711 列不了目录)。 */
    public static String readApkPaths(Context ctx) {
        try {
            android.content.pm.ApplicationInfo ai = ctx.getApplicationInfo();
            StringBuilder sb = new StringBuilder(ai.sourceDir == null ? "" : ai.sourceDir);
            if (ai.splitSourceDirs != null) {
                for (String p : ai.splitSourceDirs) {
                    if (p != null && p.length() > 0) sb.append('|').append(p);
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /* ---- 1) USB 物理连接:1/0/-1(未知) ---- */
    public static int readUsbConnected(Context ctx) {
        try {
            UsbManager um = (UsbManager) ctx.getSystemService(Context.USB_SERVICE);
            if (um != null) return um.getDeviceList().isEmpty() ? 0 : 1;
        } catch (Throwable ignored) { }
        try {
            // 退路:电池插电状态(充电也算"插着线")
            IntentFilter f = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent it = ctx.registerReceiver(null, f);
            if (it != null) {
                int plugged = it.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0);
                return plugged == 0 ? 0 : 1;
            }
        } catch (Throwable ignored) { }
        return -1;
    }

    /* ---- 2) USB 调试开关:Settings.Global.ADB_ENABLED ---- */
    public static int readAdbEnabled(Context ctx) {
        try {
            return Settings.Global.getInt(ctx.getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        } catch (Throwable t) {
            return -1;
        }
    }

    /* ---- 3) 开发者选项 ---- */
    public static int readDevelopmentSettings(Context ctx) {
        try {
            return Settings.Global.getInt(ctx.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
        } catch (Throwable t) {
            return -1;
        }
    }

    /* ---- 4) 模拟位置 ---- */
    @SuppressWarnings("deprecation")
    public static int readMockLocation(Context ctx) {
        try {
            return Settings.Secure.getInt(ctx.getContentResolver(),
                    Settings.Secure.ALLOW_MOCK_LOCATION, 0);
        } catch (Throwable t) {
            return -1;
        }
    }

    /* ---- 5) 同 uid 下的包数量(双开/多开判据,native 拿不到) ---- */
    public static int readPackagesForUidCount(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String[] pkgs = pm.getPackagesForUid(Process.myUid());
            return pkgs == null ? -1 : pkgs.length;
        } catch (Throwable t) {
            return -1;
        }
    }

    /* ---- 6) 传感器数量(模拟器通常为 0) ---- */
    public static int readSensorCount(Context ctx) {
        try {
            SensorManager sm = (SensorManager) ctx.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return -1;
            return sm.getSensorList(Sensor.TYPE_ALL).size();
        } catch (Throwable t) {
            return -1;
        }
    }

    /* ---- 7) 蓝牙 ---- */
    public static int readBluetoothAvailable() {
        try {
            return BluetoothAdapter.getDefaultAdapter() == null ? 0 : 1;
        } catch (Throwable t) {
            return -1;
        }
    }

    /* ---- 8) GL_RENDERER(模拟器 = SwiftShader/软件渲染) ----
     * 用一个 1x1 的 EGL pbuffer 拿字符串,不依赖调用方是否有 GL 上下文。 */
    public static String readGlRenderer() {
        EGLDisplay dpy = EGL14.EGL_NO_DISPLAY;
        EGLContext ctx = EGL14.EGL_NO_CONTEXT;
        EGLSurface surf = EGL14.EGL_NO_SURFACE;
        try {
            dpy = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
            int[] ver = new int[2];
            if (!EGL14.eglInitialize(dpy, ver, 0, ver, 1)) return null;
            int[] cfgAttr = { EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT,
                              EGL14.EGL_SURFACE_TYPE, EGL14.EGL_PBUFFER_BIT,
                              EGL14.EGL_NONE };
            EGLConfig[] cfgs = new EGLConfig[1];
            int[] n = new int[1];
            if (!EGL14.eglChooseConfig(dpy, cfgAttr, 0, cfgs, 0, 1, n, 0) || n[0] == 0) return null;
            int[] ctxAttr = { EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE };
            ctx = EGL14.eglCreateContext(dpy, cfgs[0], EGL14.EGL_NO_CONTEXT, ctxAttr, 0);
            int[] pb = { EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE };
            surf = EGL14.eglCreatePbufferSurface(dpy, cfgs[0], pb, 0);
            if (!EGL14.eglMakeCurrent(dpy, surf, surf, ctx)) return null;
            return GLES20.glGetString(GLES20.GL_RENDERER);
        } catch (Throwable t) {
            return null;
        } finally {
            try {
                if (dpy != EGL14.EGL_NO_DISPLAY) {
                    EGL14.eglMakeCurrent(dpy, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE,
                            EGL14.EGL_NO_CONTEXT);
                    if (surf != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(dpy, surf);
                    if (ctx != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(dpy, ctx);
                    EGL14.eglTerminate(dpy);
                }
            } catch (Throwable ignored) { }
        }
    }

    /* ---- 9) 补充:当前进程名 vs 包名(vm/双开检测的 Java 侧旁证) ---- */
    public static String describeProcess(Context ctx) {
        StringBuilder sb = new StringBuilder();
        String proc = Build.VERSION.SDK_INT >= 28
                ? android.app.Application.getProcessName() : null;
        sb.append("process=").append(proc == null ? "?" : proc);
        sb.append(" package=").append(ctx.getPackageName());
        sb.append(" uid=").append(Process.myUid());
        sb.append(" codePath=").append(ctx.getApplicationInfo().sourceDir);
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null && am.getRunningAppProcesses() != null) {
                sb.append(" runningProcs=").append(am.getRunningAppProcesses().size());
            }
        } catch (Throwable ignored) { }
        return sb.toString();
    }
}
