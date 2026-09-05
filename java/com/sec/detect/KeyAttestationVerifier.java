/* KeyAttestationVerifier.java — Key Attestation 的「验证侧」(纯 Java,可在 PC 上自测)
 *
 * 位置:java/com/sec/detect/KeyAttestationVerifier.java
 *
 * 为什么需要它(这是第 8 项之前的缺口):
 *   原来的实现只做「字段自解析」—— 把证书里的 deviceLocked / verifiedBootState 读出来就用,
 *   既不验签也不回验 challenge。后果:攻击者自己 openssl 签一张字段写好的假证书、
 *   或者把别人的旧证书喂进来(重放),检测项都会判「已锁定」。
 *   这个类补的就是那两件事:**逐级验签** + **challenge 回验**。
 *
 * 不依赖任何 android.* API(只用 java.security.cert),因此:
 *   ① 可以在 PC 上用 javac 编译 + 拿真实证书跑(见 KeyAttestationSelfTest.java);
 *   ② 服务端可以照抄/复用同一套逻辑(换成 CertPathValidator + PKIX 参数即可上生产)。
 *
 * ============ 判定四步(顺序就是判定的严格程度) ============
 *   1) 逐级验签  chain[0].verify(chain[1].公钥) … chain[n-2].verify(chain[n-1].公钥)
 *        —— 签名覆盖整张证书的 TBS(含 attestation 扩展),改一个字节就失败。
 *   2) 根信任锚  链顶必须由**调用方提供的根证书**签发(或链顶本身就是那张根)
 *        —— 没有信任锚时,"自签的假链"自己也能自洽,所以必须显式给根。
 *   3) challenge 回验  证书里的 attestationChallenge 必须逐字节等于本次下发的 nonce
 *        —— 挡重放:别人的证书/旧证书带的 challenge 对不上本次随机数。
 *   4) 字段判定  verifiedBootState==Verified && deviceLocked==true && 安全级别非 Software
 *        —— verifiedBootHash 要与官方基线比,基线只有服务端有,这里只把值带出来。
 *
 * ============ 边界(必须写在代码里,面试也会问) ============
 *   客户端跑的一切最终都在攻击者机器上:他 Frida hook 掉 verify() 让它返回 true,
 *   或者直接 patch 掉 ok() 的返回值即可绕过。所以:
 *     - 客户端自检的价值 = 挡掉"自己拿 openssl 签一张假链"这种低成本对抗 + 让 SDK 能自证;
 *     - **权威判定必须在服务端**:nonce 由服务端下发(一次性、短期过期)、链由服务端验、
 *       基线由服务端持有、结论(token/分数)由服务端签发。
 */
package com.sec.detect;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public final class KeyAttestationVerifier {

    /* Android Key Attestation 的 verifiedBootState 取值(与 AttestationParser 一致) */
    public static final int VB_VERIFIED = 0;

    /** 已知的 Google attestation 根证书 serialNumber(仅作"线索"提示,不做硬判据)。
     *  生产上正确的做法是**按指纹固定根证书**(见 rootSha256),因为根会轮换。 */
    public static final String KNOWN_GOOGLE_ROOT_SERIAL = "f92009e853b6b045";

    private KeyAttestationVerifier() {}

    /* ==================== 结果 ==================== */

    public static final class Report {
        /* 1) 链 */
        public boolean chainOk;
        public String  chainDetail = "";
        public int     chainLength;
        public String  rootSubject = "";        /* 实际用上的根证书 subject */
        public String  rootSha256 = "";         /* 根证书指纹(SHA-256,用于固定/pinning) */
        public boolean rootLooksLikeGoogle;     /* subject 里带 Google 根 serial 的线索 */

        /* 2) challenge */
        public boolean challengeOk;
        public String  challengeDetail = "";
        public String  certChallengeHex = "";
        public String  expectedNonceHex = "";

        /* 3) 字段 */
        public boolean fieldsOk;
        public String  fieldsDetail = "";
        public int     verifiedBootState = -1;
        public int     deviceLocked = -1;
        public String  securityLevel = "";
        public int     attestationSecurityLevel = -1;
        public int     keymasterSecurityLevel = -1;
        public byte[]  verifiedBootHash;
        public String  osVersion = "";
        public int     osPatchLevel = -1;       /* 202401 形式;服务端用它卡"降级攻击" */
        public int     bootPatchLevel = -1;
        public AttestationParser.Result parsed;

        /** 证明本身可信吗(链验过 + challenge 对得上) */
        public boolean trusted() { return chainOk && challengeOk; }

        /** 可信 **且** 显示"已锁定 + 启动链验证通过" —— 这才是"安全"的结论 */
        public boolean ok() { return trusted() && fieldsOk; }

        /** 一句话结论 */
        public String verdict() {
            if (!chainOk) return "REJECT: 证书链验证失败";
            if (!challengeOk) return "REJECT: challenge 未匹配(重放/未提供 nonce)";
            if (!fieldsOk) return "TRUSTED-BUT-RISK: 证明可信,但设备未锁定/启动链未验证通过";
            return "OK: 链可信 + challenge 匹配 + deviceLocked=true/Verified";
        }

        public String describe() {
            StringBuilder sb = new StringBuilder();
            sb.append("verdict: ").append(verdict()).append('\n');
            sb.append("chain  : ").append(chainOk ? "OK" : "FAIL")
              .append("(certs=").append(chainLength).append(") ").append(chainDetail).append('\n');
            if (!rootSubject.isEmpty())
                sb.append("root   : ").append(rootSubject)
                  .append(rootLooksLikeGoogle ? "  [线索:像 Google attestation 根]" : "")
                  .append('\n').append("rootFP : ").append(rootSha256).append('\n');
            sb.append("nonce  : ").append(challengeOk ? "MATCH" : "MISMATCH")
              .append(" cert=").append(certChallengeHex.isEmpty() ? "?" : certChallengeHex)
              .append(" expect=").append(expectedNonceHex.isEmpty() ? "(未提供)" : expectedNonceHex)
              .append("  ").append(challengeDetail).append('\n');
            sb.append("fields : ").append(fieldsOk ? "OK" : "RISK").append(' ')
              .append("verifiedBootState=").append(verifiedBootState)
              .append(" deviceLocked=").append(deviceLocked)
              .append(" securityLevel=").append(securityLevel.isEmpty() ? "?" : securityLevel)
              .append(" os=").append(osVersion.isEmpty() ? "?" : osVersion)
              .append("  ").append(fieldsDetail).append('\n');
            if (verifiedBootHash != null && verifiedBootHash.length > 0)
                sb.append("bootHash: ").append(AttestationParser.hex(verifiedBootHash))
                  .append("  (需与官方基线比对 —— 服务端的事)").append('\n');
            return sb.toString();
        }
    }

    /* ==================== 主入口 ==================== */

    /** 验一条证书链。chainDer 顺序不限(内部会按 subject/issuer 重排成 叶子→根)。
     *  @param chainDer  每张证书的 DER(leaf 必须带 attestation 扩展)
     *  @param expectedNonce 本次下发的 challenge;传 null 表示"没有 nonce,challenge 一律不通过"
     *        —— 因为本地拍脑袋造的 challenge 不能防重放,那种情况下"验过"没有意义。
     *  @param trustedRoots  根信任锚(用 KeyAttestation 的 Google 根证书);为空则链一律判失败 */
    public static Report verify(List<byte[]> chainDer, byte[] expectedNonce,
                                X509Certificate[] trustedRoots) {
        Report rep = new Report();
        rep.expectedNonceHex = AttestationParser.hex(expectedNonce);

        if (chainDer == null || chainDer.isEmpty()) {
            rep.chainDetail = "空证书链";
            rep.challengeDetail = "无链可验";
            rep.fieldsDetail = "无链可验";
            return rep;
        }

        /* ---- 解析 ---- */
        X509Certificate[] chain;
        try {
            chain = parseAll(chainDer);
        } catch (Exception e) {
            rep.chainDetail = "证书解析失败: " + e;
            return rep;
        }
        chain = orderChain(chain);
        rep.chainLength = chain.length;

        /* ---- 1) 逐级验签 ---- */
        StringBuilder detail = new StringBuilder();
        boolean ok = true;
        for (int i = 0; i + 1 < chain.length; i++) {
            try {
                chain[i].verify(chain[i + 1].getPublicKey());
            } catch (Exception e) {
                detail.append("chain[").append(i).append("] 签名验证失败(不是 chain[")
                      .append(i + 1).append("] 签的): ").append(e.getClass().getSimpleName()).append("; ");
                ok = false;
            }
        }

        /* ---- 2) 根信任锚 ---- */
        X509Certificate top = chain[chain.length - 1];
        X509Certificate matched = null;
        if (trustedRoots == null || trustedRoots.length == 0) {
            detail.append("未提供根证书(信任锚)→ 自签假链也能自洽,一律判失败");
            ok = false;
        } else {
            for (X509Certificate root : trustedRoots) {
                if (root == null) continue;
                if (top.equals(root)) { matched = root; break; }        /* 链顶本身就是那张根 */
                try {
                    top.verify(root.getPublicKey());                    /* 链顶由这张根签发 */
                    matched = root;
                    break;
                } catch (Exception ignored) { }
            }
            if (matched == null) {
                detail.append("链顶证书不是由任何给定根签发(issuer=")
                      .append(top.getIssuerX500Principal().getName()).append(")");
                ok = false;
            }
        }

        /* ---- 有效期:除"被 pin 的信任锚"外,其余证书过期即判失败 ----
         * 信任锚(根)过期按 PKIX 惯例不判链失败:根是硬编码/pin 的,不参与信任推导的
         * 时效判断;但要在 detail 里说出来(生产必须能更新根证书 —— 根会轮换)。
         * 这里真实的例子:Google 官方测试根 cert3 notAfter=2026-05-25,而系统时间已 2026-09。 */
        for (int i = 0; i < chain.length; i++) {
            boolean isTrustAnchor = (matched != null && i == chain.length - 1 && top.equals(matched));
            try {
                chain[i].checkValidity();
            } catch (Exception e) {
                if (isTrustAnchor) {
                    detail.append("chain[").append(i).append("] **信任锚**有效期: ").append(e.getMessage())
                          .append("(作为 pin 的根按惯例忽略;生产要能更新根证书); ");
                } else {
                    detail.append("chain[").append(i).append("] 有效期问题: ").append(e.getMessage()).append("; ");
                    ok = false;
                }
            }
        }
        rep.chainOk = ok;
        rep.chainDetail = detail.length() == 0 ? "逐级验签 + 根信任锚均通过" : detail.toString();
        if (matched != null) {
            rep.rootSubject = matched.getSubjectX500Principal().getName();
            rep.rootLooksLikeGoogle = looksLikeGoogleRoot(rep.rootSubject);
            try { rep.rootSha256 = sha256Hex(matched.getEncoded()); } catch (Exception ignored) { }
        }

        /* ---- 3) challenge 回验 + 4) 字段判定 ---- */
        AttestationParser.Result pr = parseFromChain(chain);
        if (pr == null) {
            rep.challengeDetail = "链里没有带 attestation 扩展的证书";
            rep.fieldsDetail = rep.challengeDetail;
            return rep;
        }
        rep.parsed = pr;
        rep.certChallengeHex = pr.challengeHex();

        if (expectedNonce == null || expectedNonce.length == 0) {
            rep.challengeOk = false;
            rep.challengeDetail = "未提供期望 nonce(本地自造的 challenge 不能防重放;"
                    + "必须由服务端下发后逐字节比对)";
        } else if (pr.attestationChallenge == null) {
            rep.challengeOk = false;
            rep.challengeDetail = "证书里读不到 attestationChallenge";
        } else if (!Arrays.equals(pr.attestationChallenge, expectedNonce)) {
            rep.challengeOk = false;
            rep.challengeDetail = "challenge 不匹配(重放/旧证书/伪造)";
        } else {
            rep.challengeOk = true;
        }

        rep.verifiedBootState = pr.verifiedBootState;
        rep.deviceLocked = pr.deviceLocked;
        rep.securityLevel = pr.securityLevelName();
        rep.attestationSecurityLevel = pr.attestationSecurityLevel;
        rep.keymasterSecurityLevel = pr.keymasterSecurityLevel;
        rep.verifiedBootHash = pr.verifiedBootHash;
        rep.osVersion = pr.osString();
        rep.osPatchLevel = pr.osPatchLevel;
        rep.bootPatchLevel = pr.bootPatchLevel;

        List<String> bad = new ArrayList<String>();
        if (pr.verifiedBootState != VB_VERIFIED) bad.add("verifiedBootState=" + pr.verifiedBootStateName());
        if (pr.deviceLocked != 1) bad.add("deviceLocked=" + pr.deviceLocked + "(应为 true)");
        if ("Software".equals(pr.securityLevelName())) bad.add("securityLevel=Software(无安全世界)");
        rep.fieldsOk = bad.isEmpty();
        rep.fieldsDetail = rep.fieldsOk ? "deviceLocked=true / Verified / 硬件安全级别"
                : ("未通过: " + bad);
        return rep;
    }

    /** 在链里找那张带 attestation 扩展的证书(通常是 leaf)并解析。
     *  服务端也要用同一套(别自己再写一遍)。返回 null = 链里没有 attestation 扩展。 */
    public static AttestationParser.Result parseFromChain(X509Certificate[] chain) {
        if (chain == null) return null;
        for (X509Certificate c : chain) {
            try {
                AttestationParser.Result r = AttestationParser.parseCertificate(c.getEncoded());
                if (r.found) return r;
            } catch (Exception ignored) { }
        }
        return null;
    }

    /** 便利入口:链是 base64 文本(Java 侧 KeyAttestation.chainBase64() / 服务端上报的格式) */
    public static Report verifyBase64(List<String> chainB64, byte[] expectedNonce,
                                      X509Certificate[] trustedRoots) {
        List<byte[]> der = new ArrayList<byte[]>();
        if (chainB64 != null) {
            for (String s : chainB64) {
                byte[] d = base64Decode(s);
                if (d != null && d.length > 0) der.add(d);
            }
        }
        return verify(der, expectedNonce, trustedRoots);
    }

    /* ==================== 链排序 / 解析 / 证书加载 ==================== */

    /** 按 subject/issuer 把证书排成 叶子 → 中间 → 根。排不出来(有缺失)则原样返回。 */
    public static X509Certificate[] orderChain(X509Certificate[] certs) {
        if (certs == null || certs.length <= 1) return certs;
        List<X509Certificate> pool = new ArrayList<X509Certificate>(Arrays.asList(certs));
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        X509Certificate cur = null;
        for (X509Certificate c : pool) {                 /* 叶子 = 不是任何其他证书的 issuer */
            boolean isIssuerOfOther = false;
            for (X509Certificate o : pool) {
                if (o != c && o.getIssuerX500Principal().equals(c.getSubjectX500Principal())) {
                    isIssuerOfOther = true;
                    break;
                }
            }
            if (!isIssuerOfOther) { cur = c; break; }
        }
        if (cur == null) cur = pool.get(0);
        out.add(cur);
        pool.remove(cur);
        while (!pool.isEmpty()) {
            X509Certificate next = null;
            for (X509Certificate c : pool) {
                if (c.getSubjectX500Principal().equals(cur.getIssuerX500Principal())) { next = c; break; }
            }
            if (next == null) break;                     /* 链不完整,剩下的不管 */
            out.add(next);
            pool.remove(next);
            cur = next;
        }
        return out.toArray(new X509Certificate[out.size()]);
    }

    private static X509Certificate[] parseAll(List<byte[]> chainDer) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] out = new X509Certificate[chainDer.size()];
        for (int i = 0; i < out.length; i++) {
            Object c = cf.generateCertificate(new ByteArrayInputStream(chainDer.get(i)));
            if (!(c instanceof X509Certificate)) throw new IOException("不是 X.509 证书(索引 " + i + ")");
            out[i] = (X509Certificate) c;
        }
        return out;
    }

    /** 从字节加载证书:PEM(可含多张)或单张 DER */
    public static X509Certificate[] loadCertificates(byte[] data) throws Exception {
        if (data == null || data.length == 0) return new X509Certificate[0];
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        if (isPem(data)) {
            Collection<? extends Certificate> cs =
                    cf.generateCertificates(new ByteArrayInputStream(data));
            List<X509Certificate> out = new ArrayList<X509Certificate>();
            for (Certificate c : cs) if (c instanceof X509Certificate) out.add((X509Certificate) c);
            return out.toArray(new X509Certificate[out.size()]);
        }
        return new X509Certificate[]{ (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(data)) };
    }

    public static X509Certificate[] loadCertificates(InputStream in) throws Exception {
        return loadCertificates(readAll(in));
    }

    /** 从 Java 字符串里的 PEM 文本加载(服务端最常用:配置里放 Google 根证书) */
    public static X509Certificate[] loadCertificatesFromPem(String pem) throws Exception {
        if (pem == null) return new X509Certificate[0];
        return loadCertificates(pem.getBytes("UTF-8"));
    }

    /* ==================== 小工具(零依赖,Android 23 也能用) ==================== */

    private static boolean isPem(byte[] data) {
        String head = new String(data, 0, Math.min(data.length, 64));
        return head.contains("-----BEGIN");
    }

    /** "这个根看起来像不像 Google attestation 根" —— 只是线索,不是硬判据。
     *  X500Principal.getName() 默认走 RFC2253,serialNumber 会被打印成 OID 形式
     *  (2.5.4.5=#1310<hex>),所以明文和 hex 两种形式都要认。
     *  ★ 生产上的正确做法是**按指纹 pin**(rootSha256),而不是靠 subject 字符串。 */
    private static boolean looksLikeGoogleRoot(String subject) {
        if (subject == null) return false;
        if (subject.contains(KNOWN_GOOGLE_ROOT_SERIAL)) return true;
        try {
            return subject.contains(
                    AttestationParser.hex(KNOWN_GOOGLE_ROOT_SERIAL.getBytes("UTF-8")));
        } catch (Exception e) {
            return false;
        }
    }

    public static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return AttestationParser.hex(md.digest(data));
        } catch (Exception e) {
            return "";
        }
    }

    /** 公钥指纹(SHA-256),用于和基线/服务端记录交叉核对 */
    public static String publicKeySha256Hex(X509Certificate cert) {
        PublicKey pk = cert.getPublicKey();
        return pk == null ? "" : sha256Hex(pk.getEncoded());
    }

    /* --- base64:自己实现,不依赖 android.util.Base64 / java.util.Base64(API 26 才有) --- */

    public static byte[] base64Decode(String s) {
        if (s == null) return null;
        String t = s.replaceAll("\\s", "").replace('-', '+').replace('_', '/');
        int pad = 0;
        while (t.endsWith("=")) { t = t.substring(0, t.length() - 1); pad++; }
        if (pad > 2) return null;
        int outLen = t.length() * 3 / 4;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(outLen);
        int buf = 0, bits = 0;
        for (int i = 0; i < t.length(); i++) {
            int v = B64.indexOf(t.charAt(i));
            if (v < 0) return null;
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                bos.write((buf >> bits) & 0xFF);
            }
        }
        return bos.toByteArray();
    }

    public static String base64Encode(byte[] data) {
        if (data == null) return "";
        StringBuilder sb = new StringBuilder(((data.length + 2) / 3) * 4);
        int i = 0;
        while (i + 2 < data.length) {
            int n = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8) | (data[i + 2] & 0xFF);
            sb.append(B64.charAt((n >> 18) & 63)).append(B64.charAt((n >> 12) & 63))
              .append(B64.charAt((n >> 6) & 63)).append(B64.charAt(n & 63));
            i += 3;
        }
        int rem = data.length - i;
        if (rem == 1) {
            int n = (data[i] & 0xFF) << 16;
            sb.append(B64.charAt((n >> 18) & 63)).append(B64.charAt((n >> 12) & 63)).append("==");
        } else if (rem == 2) {
            int n = ((data[i] & 0xFF) << 16) | ((data[i + 1] & 0xFF) << 8);
            sb.append(B64.charAt((n >> 18) & 63)).append(B64.charAt((n >> 12) & 63))
              .append(B64.charAt((n >> 6) & 63)).append('=');
        }
        return sb.toString();
    }

    private static final String B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}
