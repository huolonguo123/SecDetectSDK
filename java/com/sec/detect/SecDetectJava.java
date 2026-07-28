/* SecDetectJava.java — SecDetect SDK 的 Java 门面(推荐入口)
 *
 * 位置:java/com/sec/detect/SecDetectJava.java
 *
 * 把"集成方要做的三件事"包成三个方法,避免直接在业务代码里
 * 拼 native 调用:
 *
 *   1) prepare(ctx):回填环境事实(USB/ADB/开发者选项/传感器/GL/
 *      同 uid 包数/硬件密钥)+ Key Attestation(TEE 证明)
 *   2) scan(ctx, apkPath):跑全项扫描,拿到结果
 *   3) signatureMd5(ctx):拿当前 APK 的**签名证书 MD5**,交给 CI 当
 *      第 7 项(repack)的基线 —— 与 keytool/apksigner 的输出一致
 *
 * 用法(示例):
 *     SecDetectBridge.officialSignatureBaseline = "ceda68c1...";   // 构建期固化/服务端下发
 *     SecDetectJava.prepare(getApplicationContext());              // 回填(含自身 APK 路径)
 *     SecDetectJava.Result r = SecDetectJava.scan(getApplicationContext(), null);
 *     if (r.risk) Log.w("SecDetect", r.output);
 *
 *     // 只做重打包校验也应该"不传路径":路径与基线都走 env facts
 *     SecDetectJava.Result sig = SecDetectJava.checkRepack();
 *
 *     // CI 里生成官方基线(存进发布配置):
 *     String md5 = SecDetectJava.signatureMd5(ctx);
 */
package com.sec.detect;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.security.MessageDigest;

public final class SecDetectJava {

    public static final class Result {
        public final int code;      // -1 参数错 / 0 干净 / 1 有风险
        public final String output; // 证据串(DETECT_ALL 时每项一行)
        public final boolean risk;
        public Result(int code, String output) {
            this.code = code;
            this.output = output;
            this.risk = code == 1;
        }
        @Override public String toString() { return "[" + code + "] " + output; }
    }

    private SecDetectJava() {}

    /** 三步预处理:环境事实 + 硬件密钥 + Key Attestation(TEE)。失败不抛异常。 */
    public static void prepare(Context ctx) {
        try {
            SecDetectBridge.collectAndPush(ctx);
        } catch (Throwable ignored) { }
        try {
            KeyAttestation.collectAndPush();     // 较慢(生成密钥),建议只调一次
        } catch (Throwable ignored) { }
    }

    /** Key Attestation 的**验证侧**配置 + 采集(推荐入口)。
     *
     * @param serverNonce          服务端下发的一次性 nonce(null = 本地随机,不防重放,只做自检)
     * @param googleRootPem        Google attestation 根证书 PEM(信任锚;null = 不做自检,回填 -1)
     * @param bootHashBaselineHex  官方 verifiedBootHash 基线(可空;给了才能判"镜像是否被改")
     * @return null = 成功,否则是错误说明
     *
     * ★ 这一段只是"客户端自检 + 采集"。权威判定在服务端:服务端自己出 nonce、自己验链、
     *   自己比基线 —— 客户端自检可被 hook 绕过(见 KeyAttestationVerifier 头注释)。
     * 典型用法:
     *     String nonce = http.get("/attest/challenge");                 // 服务端下发
     *     SecDetectJava.prepareAttestation(AttestationParser.fromHex(nonce),
     *                                      GOOGLE_ROOT_PEM, null);
     *     http.post("/attest/verify", KeyAttestation.chainBase64());    // 整条链上报
     */
    public static String prepareAttestation(byte[] serverNonce, String googleRootPem,
                                            String bootHashBaselineHex) {
        try {
            KeyAttestation.setChallenge(serverNonce);
            if (bootHashBaselineHex != null) {
                KeyAttestation.setVerifiedBootHashBaselineHex(bootHashBaselineHex);
            }
            if (googleRootPem != null) {
                String err = KeyAttestation.setTrustedRootsFromPem(googleRootPem);
                if (err != null) return err;
            }
            return KeyAttestation.collectAndPush();
        } catch (Throwable t) {
            return "prepareAttestation failed: " + t;
        }
    }

    /** 最近一次 Key Attestation 自检报告(null = 没做自检);详见 KeyAttestationVerifier.Report */
    public static KeyAttestationVerifier.Report attestationReport() {
        return KeyAttestation.lastReport();
    }

    /** 全项扫描(12 项)。apkPath 传 null 即可 —— 重打包项会使用
     *  prepare() 回填的自身 APK 路径与基线(见 SecDetectBridge.readApkPaths)。 */
    public static Result scan(Context ctx, String apkPath) {
        SecDetectBridge.Result r = SecDetectBridge.detect(SecDetectBridge.DETECT_ALL, apkPath);
        return new Result(r.code, r.evidence);
    }

    /** 只做重打包校验:不需要传任何路径。 */
    public static Result checkRepack() {
        return scanOne(SecDetectBridge.DETECT_REPACK, null);
    }

    /** 单测一项。 */
    public static Result scanOne(int detectType, String input) {
        SecDetectBridge.Result r = SecDetectBridge.detect(detectType, input);
        return new Result(r.code, r.evidence);
    }

    /* ================= 签名指纹(重打包检测的基线来源) ================= */

    /** 当前 APK 签名证书的 MD5(小写 hex);失败返回 null */
    public static String signatureMd5(Context ctx) {
        Signature sig = firstSignature(ctx);
        return sig == null ? null : hex(digest("MD5", sig.toByteArray()));
    }

    /** 当前 APK 签名证书的 SHA-256(小写 hex);失败返回 null */
    public static String signatureSha256(Context ctx) {
        Signature sig = firstSignature(ctx);
        return sig == null ? null : hex(digest("SHA-256", sig.toByteArray()));
    }

    /** 所有签名摘要(多签名/历史签名场景) */
    public static String describeSignatures(Context ctx) {
        StringBuilder sb = new StringBuilder();
        try {
            PackageManager pm = ctx.getPackageManager();
            PackageInfo pi;
            if (Build.VERSION.SDK_INT >= 28) {
                pi = pm.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo si = pi.signingInfo;
                if (si != null && si.hasMultipleSigners() && si.getApkContentsSigners() != null) {
                    for (Signature s : si.getApkContentsSigners())
                        sb.append("md5=").append(md5(s)).append(" ");
                } else if (si != null && si.getSigningCertificateHistory() != null) {
                    for (Signature s : si.getSigningCertificateHistory())
                        sb.append("md5=").append(md5(s)).append(" ");
                }
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo piOld = pm.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNATURES);
                if (piOld.signatures != null)
                    for (Signature s : piOld.signatures)
                        sb.append("md5=").append(md5(s)).append(" ");
            }
        } catch (Throwable t) {
            return "error: " + t;
        }
        return sb.toString().trim();
    }

    private static Signature firstSignature(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo si = pi.signingInfo;
                if (si == null) return null;
                Signature[] arr = si.hasMultipleSigners()
                        ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
                return (arr == null || arr.length == 0) ? null : arr[0];
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(ctx.getPackageName(),
                        PackageManager.GET_SIGNATURES);
                return (pi.signatures == null || pi.signatures.length == 0) ? null : pi.signatures[0];
            }
        } catch (Throwable t) {
            return null;
        }
    }

    private static String md5(Signature s) {
        return hex(digest("MD5", s.toByteArray()));
    }

    /** MessageDigest 包装:算法不可用时返回 null,不抛异常 */
    private static byte[] digest(String algo, byte[] data) {
        try {
            return MessageDigest.getInstance(algo).digest(data);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String hex(byte[] b) {
        if (b == null) return null;
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
