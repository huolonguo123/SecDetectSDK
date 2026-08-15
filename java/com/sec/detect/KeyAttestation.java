/* KeyAttestation.java — Google Key Attestation(硬件密钥证明)的采集 + 自检 + 回填
 *
 * 位置:java/com/sec/detect/KeyAttestation.java
 *
 * ============ 它在整个流程里的位置(采集侧) ============
 *   服务端下发 nonce  →  setChallenge(nonce)  →  生成带这个 challenge 的密钥
 *   →  取证书链(KeyDescription 里有 TEE 填的 deviceLocked / verifiedBootState)
 *   →  ① 上报整条链给服务端(base64,服务端验签+比 nonce+比基线)
 *      ② 本地自检(KeyAttestationVerifier:逐级验签 + 回验 challenge)
 *      ③ 把解析出的字段 + 自检结论回填给 native(det_bootloader.cpp 消费)
 *
 * ============ 为什么 challenge 必须"可注入"(这是防重放的关键) ============
 *   旧实现用 "secdetect-" + System.currentTimeMillis() 当场造一个 challenge:
 *     - 题目可预测(hook 掉 currentTimeMillis 就变成固定值);
 *     - 攻击者能在真机(已锁定的备用机)上"提前办一张固定题目的证书"存起来复用;
 *     - 收到证书后也没人回验它 == 刚才那个值,所以重放真证书照样通过。
 *   正确姿势:nonce 由**服务端随机生成、一次性、短期过期**,App 拿它去办证;
 *   服务端收到证书后比对"证书里的 attestationChallenge == 自己刚发的那个"。
 *   本类的 setChallenge(nonce) 就是给这条链路留的入口;
 *   没有服务端时(纯自检模式)退回 SecureRandom 32 字节 —— 比时间戳强,
 *   但**仍然不能防重放**,所以那种情况下自检结果只作参考(见 README「限制」)。
 *
 * ============ 边界(务必写清) ============
 *   客户端自检跑在攻击者机器上:他可以 hook 掉 verify() 或 patch 返回值。
 *   所以自检结论(att_chain_verified)只能"提高绕过成本",权威判定必须在服务端。
 */
package com.sec.detect;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

public final class KeyAttestation {

    private static final String KEY_ALIAS = "secdetect_attest_key";

    private static int sHwKey = -1;                    /* 缓存:是否硬件密钥 */
    private static boolean sAttested = false;

    /* --- 验证侧的状态 --- */
    private static volatile byte[] sChallenge;          /* 期望的 challenge(服务端下发;null = 自造) */
    private static volatile byte[] sUsedChallenge;      /* 当前这把密钥生成时用的 challenge */
    private static volatile X509Certificate[] sTrustedRoots;   /* 自检用的根信任锚(Google 根证书) */
    private static volatile String sBootHashBaselineHex = "";  /* 官方 verifiedBootHash 基线(可选) */
    private static volatile List<String> sLastChain;    /* 最近一次取到的链(base64,供上报服务端) */
    private static volatile KeyAttestationVerifier.Report sLastReport;
    private static volatile String sLastError = "";

    private KeyAttestation() {}

    /* ================= 1) 验证侧配置(集成方调用) ================= */

    /** 设置期望的 challenge(服务端下发的一次性随机数,建议 16~32 字节)。
     *  注意:改 challenge 会让**旧密钥失效并重新生成**(challenge 绑在密钥/证书上)。
     *  传 null 表示回到"本地 SecureRandom 自造"模式(无服务端时的退路)。 */
    public static void setChallenge(byte[] nonce) {
        sChallenge = (nonce == null) ? null : nonce.clone();
    }

    /** 当前的 challenge(发给服务端做比对/日志用) */
    public static byte[] currentChallenge() {
        byte[] c = sUsedChallenge;
        return c == null ? null : c.clone();
    }

    /** 根信任锚:Google attestation 根证书(一条链可能有多张,按 PEM 加载)。
     *  没有它 → 自检判定为"未知"(-1),不会误报"链有问题"。 */
    public static void setTrustedRoots(X509Certificate[] roots) {
        sTrustedRoots = roots;
    }

    /** 从 PEM 文本设置根信任锚(服务端/CI 下发,或打包进 assets) */
    public static String setTrustedRootsFromPem(String pem) {
        try {
            sTrustedRoots = KeyAttestationVerifier.loadCertificatesFromPem(pem);
            return sTrustedRoots.length == 0 ? "no certificate found in pem" : null;
        } catch (Throwable t) {
            return "load roots failed: " + t;
        }
    }

    /** 官方 verifiedBootHash 基线(16 进制,64 字符 = 32 字节)。
     *  ★ 与 apk_baseline 同理:只能由 CI/服务端下发,**不要**用"第一次跑到的值"当基线。 */
    public static void setVerifiedBootHashBaselineHex(String hex) {
        sBootHashBaselineHex = hex == null ? "" : hex.trim().toLowerCase();
    }

    /* ================= 2) 是否硬件支持的密钥(TEE/StrongBox)================== */

    /** 返回 1=硬件支持(TEE),0=仅软件,-1=失败/未知。结果缓存。 */
    public static synchronized int probeHardwareKey() {
        if (sHwKey != -1) return sHwKey;
        try {
            ensureAttestedKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey pk = (PrivateKey) ks.getKey(KEY_ALIAS, null);
            if (pk == null) { sHwKey = -1; return sHwKey; }
            KeyFactory kf = KeyFactory.getInstance(pk.getAlgorithm(), "AndroidKeyStore");
            KeyInfo ki = (KeyInfo) kf.getKeySpec(pk, KeyInfo.class);
            sHwKey = ki.isInsideSecureHardware() ? 1 : 0;
        } catch (Throwable t) {
            sHwKey = -1;
        }
        return sHwKey;
    }

    /* ================= 3) 取链(供上报服务端) ================= */

    /** 取整条证书链的 base64(leaf → 中间 → 根)。这是要交给**服务端**验签的原料;
     *  客户端解析出来的字段只是"便于本地判定",不能替代链本身。 */
    public static synchronized List<String> chainBase64() {
        try {
            ensureAttestedKey();
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain(KEY_ALIAS);
            List<String> out = new ArrayList<String>();
            if (chain != null) {
                for (Certificate c : chain) {
                    out.add(KeyAttestationVerifier.base64Encode(c.getEncoded()));
                }
            }
            sLastChain = out;
            return out;
        } catch (Throwable t) {
            sLastError = "chainBase64 failed: " + t;
            return new ArrayList<String>();
        }
    }

    /** 最近一次取到的链(base64) */
    public static List<String> lastChain() { return sLastChain; }

    /** 最近一次自检报告(null = 没做自检:缺 nonce 或缺根信任锚) */
    public static KeyAttestationVerifier.Report lastReport() { return sLastReport; }

    public static String lastError() { return sLastError; }

    /* ================= 4) 采集 + 自检 + 回填 ================= */

    /** 采集并回填给 native;返回 null 表示成功,否则返回错误说明(便于日志)。 */
    public static String collectAndPush() {
        try {
            ensureAttestedKey();
            List<String> chain = chainBase64();
            if (chain.isEmpty()) return "no certificate chain";

            /* --- 解析:找带 attestation 扩展的那张(通常是 leaf) --- */
            AttestationParser.Result res = null;
            for (String b64 : chain) {
                byte[] der = KeyAttestationVerifier.base64Decode(b64);
                if (der == null) continue;
                AttestationParser.Result r = AttestationParser.parseCertificate(der);
                if (r.found) { res = r; break; }
            }
            if (res == null) return "no attestation extension in chain (device has no TEE attestation?)";

            /* --- 客户端自检:逐级验签 + challenge 回验 ---
             * 只有"有 nonce"且"有根信任锚"时才做 —— 否则结论没有意义,
             * 用 -1(未知)回填,检测项不会据此误报。 */
            KeyAttestationVerifier.Report rep = null;
            if (sChallenge != null && sTrustedRoots != null && sTrustedRoots.length > 0) {
                rep = KeyAttestationVerifier.verifyBase64(chain, sChallenge, sTrustedRoots);
            }
            sLastReport = rep;
            int chainVerified = (rep == null) ? -1 : (rep.trusted() ? 1 : 0);

            /* swEnforced:安全级别是 Software 就等于"用户态可伪造" */
            int swEnforced = res.softwareOnly() ? 1 : 0;
            /* hashOk:只有拿到官方基线才能判;否则 -1(未知),服务端再比 */
            int hashOk = checkBootHash(res.verifiedBootHash);

            SecDetectBridge.nativeSetAttestation(
                    new int[]{res.verifiedBootState, res.deviceLocked,
                              hashOk, swEnforced, chainVerified},
                    new String[]{res.osString(), res.securityLevelName()});
            sAttested = true;
            sLastError = "";
            return null;
        } catch (Throwable t) {
            sLastError = "key attestation failed: " + t;
            return sLastError;
        }
    }

    /** 与服务端提供的官方基线比对启动链哈希;-1 = 没有基线,无法判定 */
    private static int checkBootHash(byte[] hash) {
        if (hash == null || hash.length == 0) return -1;
        String base = sBootHashBaselineHex;
        if (base == null || base.isEmpty()) return -1;
        return AttestationParser.hex(hash).equals(base) ? 1 : 0;
    }

    public static boolean attested() { return sAttested; }

    /** 供本地日志看的摘要 */
    public static String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("hwKey=").append(probeHardwareKey());
        sb.append(" attested=").append(sAttested);
        sb.append(" android=").append(Build.VERSION.RELEASE);
        sb.append(" mode=").append(sChallenge == null ? "local-random(不防重放)" : "server-nonce");
        sb.append(" roots=").append(sTrustedRoots == null ? 0 : sTrustedRoots.length);
        if (sLastReport != null) sb.append(" selfcheck=").append(sLastReport.verdict());
        return sb.toString();
    }

    /* ================= 内部:生成带 attestation challenge 的密钥 ================= */

    private static void ensureAttestedKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        byte[] want = (sChallenge != null) ? sChallenge : randomChallenge();

        /* 密钥已存在且 challenge 没变 → 直接复用(challenge 变更必须重新办证) */
        if (ks.containsAlias(KEY_ALIAS)) {
            if (sUsedChallenge != null && java.util.Arrays.equals(sUsedChallenge, want)) return;
            try { ks.deleteEntry(KEY_ALIAS); } catch (Throwable ignored) { }
        }

        /* 先试 StrongBox(更硬的证明),失败退回 TEE */
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                generate(ks, want, true);
                sUsedChallenge = want;
                return;
            } catch (Throwable ignored) {
                /* 无 StrongBox,继续走 TEE */
            }
        }
        generate(ks, want, false);
        sUsedChallenge = want;
    }

    private static void generate(KeyStore ks, byte[] challenge, boolean strongBox) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge);
        if (strongBox) b.setIsStrongBoxBacked(true);
        kpg.initialize(b.build());
        kpg.generateKeyPair();
    }

    /** 无服务端时的退路:32 字节 SecureRandom。比时间戳强(不可预测、每次不同),
     *  但**不能防重放** —— 攻击者可以让它恒返回同一个值来预办证。 */
    private static byte[] randomChallenge() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
}
