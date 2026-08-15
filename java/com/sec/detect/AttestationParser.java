/*
 * AttestationParser.java — Android Key Attestation 扩展的纯 Java 解析器
 *
 * 位置:java/com/sec/detect/AttestationParser.java
 *
 * 为什么单独一个文件:**它不依赖任何 android.* API**,所以可以在 PC 上用
 * 普通 javac 直接编译 + 拿真实 attestation 证书做自测(见
 * AttestationParserSelfTest.java)。KeyAttestation.java 负责"取证书"
 * (需要 KeyStore),这里只负责"解字节"。
 *
 * ================== ASN.1 结构(关键,踩过坑) ==================
 * 证书里的扩展 OID 1.3.6.1.4.1.11129.2.1.17,extnValue 是包了一层的
 * OCTET STRING,里面才是 KeyDescription:
 *
 *   KeyDescription ::= SEQUENCE {
 *     attestationVersion       INTEGER,
 *     attestationSecurityLevel ENUMERATED,     <- 索引 1
 *     keymasterVersion         INTEGER,
 *     keymasterSecurityLevel   ENUMERATED,     <- 索引 3
 *     attestationChallenge     OCTET STRING,
 *     uniqueId                 OCTET STRING,
 *     softwareEnforced         AuthorizationList,   <- SEQUENCE,索引 6
 *     teeEnforced              AuthorizationList    <- SEQUENCE,索引 7
 *   }
 *   AuthorizationList ::= SEQUENCE { ... [tag] EXPLICIT value ... }
 *
 * ★ 每个带标签的条目都是 **EXPLICIT** 标记(实测真实证书确认):
 *     704 [0xBF 0x85 0x40] 30 ..   <- rootOfTrust 里还包一层 SEQUENCE
 *     705 [0xBF 0x85 0x41] 02 01 00 <- osVersion 里还包一层 INTEGER
 *   所以拿到条目后必须"再解一层"才能读到真正的值。
 *   最初的实现按 IMPLICIT 处理(直接把条目内容当 RootOfTrust 的字段序列),
 *   结果 deviceLocked / verifiedBootState 全部读不到 → 静默判成"未知",
 *   **解锁的机器也报不出来**。这个 bug 就是靠拿 Google 官方测试证书跑
 *   自测发现的(见 docs/改动说明 §9 的验证记录)。
 *
 *   RootOfTrust ::= SEQUENCE {
 *     verifiedBootKey   OCTET STRING,
 *     deviceLocked      BOOLEAN,        <- 0 = bootloader 已解锁
 *     verifiedBootState ENUMERATED,     <- 0 Verified 1 SelfSigned 2 Unverified 3 Failed
 *     verifiedBootHash  OCTET STRING OPTIONAL
 *   }
 *   其他用到的标签:705 osVersion、706 osPatchLevel、718 vendorPatchLevel、
 *   719 bootPatchLevel(整数,均 EXPLICIT 包裹)。
 *
 * 注意:高标签号(>30)用 high-tag-number 形式编码(如 704 = BF 85 40),
 * 解析器必须支持,否则连标签都认不出来。
 */
package com.sec.detect;

import java.util.Arrays;

public final class AttestationParser {

    /** Android Key Attestation 扩展 OID 的 DER 编码(06 0A 2B 06 01 04 01 D6 79 02 01 11) */
    private static final byte[] OID_DER =
            {0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0xD6, 0x79, 0x02, 0x01, 0x11};

    public static final int SL_SOFTWARE = 0;
    public static final int SL_TEE = 1;
    public static final int SL_STRONGBOX = 2;

    public static final int VB_VERIFIED = 0;
    public static final int VB_SELF_SIGNED = 1;
    public static final int VB_UNVERIFIED = 2;
    public static final int VB_FAILED = 3;

    /* Keymaster AuthorizationList 标签号(AOSP keymaster_defs.h) */
    private static final int KM_TAG_ROOT_OF_TRUST = 704;
    private static final int KM_TAG_OS_VERSION = 705;
    private static final int KM_TAG_OS_PATCHLEVEL = 706;
    private static final int KM_TAG_VENDOR_PATCHLEVEL = 718;
    private static final int KM_TAG_BOOT_PATCHLEVEL = 719;

    private AttestationParser() {}

    /** 解析结果;found=false 表示这张证书没有 attestation 扩展 */
    public static final class Result {
        public boolean found;
        public String error;

        public int attestationSecurityLevel = -1;
        public int keymasterSecurityLevel = -1;
        public int verifiedBootState = -1;
        public int deviceLocked = -1;        /* 1 已锁 0 已解锁 -1 未知 */
        public int osVersion = -1;
        public int osPatchLevel = -1;
        public int vendorPatchLevel = -1;
        public int bootPatchLevel = -1;
        public int verifiedBootHashLen = -1;

        /** attestationChallenge 的原始字节:TEE 会把请求方给的字节原样写进 KeyDescription,
         *  并且这段内容**被签名覆盖**。所以"证书里的 challenge == 本次下发的 nonce"
         *  无法被攻击者篡改 —— 这是防重放(旧证书/别人的证书)的唯一抓手。
         *  ★ 之前这里被跳过(cur.next() 丢弃):拿到证书也证明不了"是这次现签的"。 */
        public byte[] attestationChallenge;

        /** rootOfTrust.verifiedBootHash 的原始字节(启动链哈希)。
         *  要与**官方基线**比对才有意义 —— 基线只能由服务端/CI 持有,所以这里只把值带出来。 */
        public byte[] verifiedBootHash;

        public boolean softwareOnly() {
            return attestationSecurityLevel == SL_SOFTWARE || keymasterSecurityLevel == SL_SOFTWARE;
        }

        public String securityLevelName() {
            int sl = attestationSecurityLevel >= 0 ? attestationSecurityLevel : keymasterSecurityLevel;
            if (sl == SL_TEE) return "TEE";
            if (sl == SL_STRONGBOX) return "StrongBox";
            if (sl == SL_SOFTWARE) return "Software";
            return "";
        }

        public String verifiedBootStateName() {
            switch (verifiedBootState) {
                case VB_VERIFIED: return "Verified";
                case VB_SELF_SIGNED: return "SelfSigned";
                case VB_UNVERIFIED: return "Unverified";
                case VB_FAILED: return "Failed";
                default: return "Unknown";
            }
        }

        /** 给人看的版本串,如 "osVersion=33 patch=2024-01" */
        public String osString() {
            if (osVersion < 0 && osPatchLevel < 0) return "";
            return "osVersion=" + osVersion + " patch=" + patchName(osPatchLevel);
        }

        /* ---- challenge / bootHash 的十六进制视图(比对日志、上报服务端都用得上) ---- */

        public String challengeHex() { return hex(attestationChallenge); }

        public String verifiedBootHashHex() { return hex(verifiedBootHash); }

        /** 与"本次下发的 nonce"逐字节比对(服务端/客户端自检的判定点) */
        public boolean challengeMatches(byte[] expected) {
            return expected != null && expected.length > 0
                    && attestationChallenge != null
                    && Arrays.equals(attestationChallenge, expected);
        }

        @Override public String toString() {
            return "found=" + found
                    + " securityLevel=" + securityLevelName()
                    + " keymasterSL=" + keymasterSecurityLevel
                    + " verifiedBootState=" + verifiedBootStateName() + "(" + verifiedBootState + ")"
                    + " deviceLocked=" + deviceLocked
                    + " challenge=" + (attestationChallenge == null
                            ? "?" : (attestationChallenge.length + "B:" + challengeHex()))
                    + " bootHash=" + (verifiedBootHash == null ? "?" : verifiedBootHashHex())
                    + " " + osString()
                    + (error == null ? "" : " error=" + error);
        }
    }

    /* ==================== 对外入口 ==================== */

    /** 从 X.509 证书 DER(X509Certificate.getEncoded())解析 */
    public static Result parseCertificate(byte[] certDer) {
        Result r = new Result();
        if (certDer == null || certDer.length < 16) { r.error = "empty certificate"; return r; }
        byte[] kd = findKeyDescription(certDer);
        if (kd == null) { r.error = "no attestation extension"; return r; }
        return parseKeyDescription(kd);
    }

    /** 从 KeyDescription 的 DER 解析(extnValue 已剥掉外层 OCTET STRING) */
    public static Result parseKeyDescription(byte[] kd) {
        Result r = new Result();
        Tlv root = Tlv.read(kd, 0);
        if (root == null || root.tag != T_SEQUENCE) { r.error = "key description is not a SEQUENCE"; return r; }

        Cursor cur = new Cursor(kd, root.valueOffset, root.length);
        Tlv attestationVersion = cur.next();          /* INTEGER */
        Tlv attSL = cur.next();                       /* ENUMERATED */
        Tlv keymasterVersion = cur.next();            /* INTEGER */
        Tlv kmSL = cur.next();                        /* ENUMERATED */
        Tlv challenge = cur.next();                   /* challenge   OCTET STRING —— 存下来! */
        cur.next();                                   /* uniqueId    OCTET STRING */
        Tlv softwareEnforced = cur.next();            /* SEQUENCE */
        Tlv teeEnforced = cur.next();                 /* SEQUENCE */

        r.attestationSecurityLevel = attSL == null ? -1 : (int) attSL.intValue();
        r.keymasterSecurityLevel = kmSL == null ? -1 : (int) kmSL.intValue();

        /* teeEnforced 是权威来源;softwareEnforced 作为补充(老设备可能只放这边) */
        if (teeEnforced != null) parseAuthList(kd, teeEnforced, r, true);
        if (softwareEnforced != null) parseAuthList(kd, softwareEnforced, r, false);

        /* challenge:KeyDescription 的第 5 个字段(索引 4)。
         * 它同时被 TEE 写进证书并被签名覆盖 → 回验它 = 证明"这张证书是本次现签的"。 */
        if (challenge != null && challenge.tag == T_OCTET_STRING) r.attestationChallenge = challenge.bytes();

        r.found = true;
        return r;
    }

    /* ==================== AuthorizationList ==================== */

    private static void parseAuthList(byte[] d, Tlv list, Result r, boolean authoritative) {
        Cursor cur = new Cursor(d, list.valueOffset, list.length);
        Tlv tagged;
        while ((tagged = cur.next()) != null) {
            /* ★ EXPLICIT 标记:条目内容本身还是一个 TLV,先解一层 */
            Tlv v = explicit(d, tagged);
            switch (tagged.tag) {
                case KM_TAG_ROOT_OF_TRUST: {
                    if (v.tag != T_SEQUENCE) break;
                    Cursor rot = new Cursor(d, v.valueOffset, v.length);
                    Tlv bootKey = rot.next();          /* OCTET STRING */
                    Tlv locked = rot.next();           /* BOOLEAN */
                    Tlv state = rot.next();            /* ENUMERATED */
                    Tlv hash = rot.next();             /* OCTET STRING(可选) */
                    if (bootKey != null && bootKey.tag != T_OCTET_STRING) break;   /* 结构不对,别乱读 */
                    if (locked != null && locked.tag == T_BOOLEAN
                            && (authoritative || r.deviceLocked < 0)) {
                        r.deviceLocked = locked.booleanValue() ? 1 : 0;
                    }
                    if (state != null && state.tag == T_ENUMERATED
                            && (authoritative || r.verifiedBootState < 0)) {
                        r.verifiedBootState = (int) state.intValue();
                    }
                    if (hash != null && hash.tag == T_OCTET_STRING) {
                        r.verifiedBootHashLen = hash.length;
                        r.verifiedBootHash = hash.bytes();   /* 值也带出来(服务端比基线用) */
                    }
                    break;
                }
                case KM_TAG_OS_VERSION:
                    if (authoritative || r.osVersion < 0) r.osVersion = (int) v.intValue();
                    break;
                case KM_TAG_OS_PATCHLEVEL:
                    if (authoritative || r.osPatchLevel < 0) r.osPatchLevel = (int) v.intValue();
                    break;
                case KM_TAG_VENDOR_PATCHLEVEL:
                    if (authoritative || r.vendorPatchLevel < 0) r.vendorPatchLevel = (int) v.intValue();
                    break;
                case KM_TAG_BOOT_PATCHLEVEL:
                    if (authoritative || r.bootPatchLevel < 0) r.bootPatchLevel = (int) v.intValue();
                    break;
                default:
                    break;
            }
        }
    }

    /** EXPLICIT 标记:内容还是一个合法 TLV 就解一层;否则原样返回(容错) */
    private static Tlv explicit(byte[] d, Tlv tagged) {
        Tlv inner = Tlv.read(d, tagged.valueOffset);
        if (inner != null && inner.end() <= tagged.end() && inner.headerLength() >= 2) return inner;
        return tagged;
    }

    /* ==================== 定位扩展 ==================== */

    /** 在证书里找 attestation 扩展,返回 【内层 KeyDescription 的 DER 拷贝】 */
    private static byte[] findKeyDescription(byte[] d) {
        for (int off = 0; off + 2 + OID_DER.length <= d.length; off++) {
            if (d[off] != 0x06 || d[off + 1] != (byte) OID_DER.length) continue;
            if (!matches(d, off + 2, OID_DER)) continue;
            Tlv extnValue = Tlv.read(d, off + 2 + OID_DER.length);   /* OCTET STRING */
            if (extnValue == null || extnValue.tag != T_OCTET_STRING) continue;
            Tlv kd = Tlv.read(d, extnValue.valueOffset);             /* 里面才是 SEQUENCE */
            if (kd == null) continue;
            return Arrays.copyOfRange(d, kd.offset, kd.end());
        }
        return null;
    }

    private static boolean matches(byte[] d, int off, byte[] pat) {
        if (off + pat.length > d.length) return false;
        for (int i = 0; i < pat.length; i++) if (d[off + i] != pat[i]) return false;
        return true;
    }

    private static String patchName(int patch) {
        if (patch < 0) return "?";
        return String.format("%04d-%02d", patch / 100, patch % 100);
    }

    /* ==================== 十六进制视图(日志/上报/自测都用) ==================== */

    /** 小写十六进制(null / 空 → "") */
    public static String hex(byte[] b) {
        if (b == null || b.length == 0) return "";
        final char[] d = "0123456789abcdef".toCharArray();
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(d[(x >> 4) & 0xF]).append(d[x & 0xF]);
        return sb.toString();
    }

    /** 十六进制串 → 字节;非法字符返回 null */
    public static byte[] fromHex(String s) {
        if (s == null) return null;
        String t = s.trim();
        if ((t.length() & 1) != 0) return null;
        byte[] out = new byte[t.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(t.charAt(i * 2), 16);
            int lo = Character.digit(t.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) return null;
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /* ==================== 极简 TLV 读取 ==================== */

    private static final int T_BOOLEAN = 1;
    private static final int T_INTEGER = 2;
    private static final int T_OCTET_STRING = 4;
    private static final int T_ENUMERATED = 10;
    private static final int T_SEQUENCE = 16;      /* 0x30 & 0x1F */

    /** 保存的是"在原始数组里的绝对偏移",不做切片,避免偏移错乱 */
    private static final class Tlv {
        byte[] d;
        int offset;        /* 起始(含 tag/len) */
        int tag;           /* 标签号(已展开 high-tag-number) */
        int valueOffset;   /* 内容起始 */
        int length;        /* 内容长度 */

        int end() { return valueOffset + length; }
        int headerLength() { return valueOffset - offset; }

        static Tlv read(byte[] d, int off) {
            if (d == null || off < 0 || off >= d.length) return null;
            Tlv t = new Tlv();
            t.d = d;
            t.offset = off;
            int p = off;
            int first = d[p++] & 0xFF;
            int tag = first & 0x1F;
            if (tag == 0x1F) {                       /* high-tag-number:704 → 0xBF 0x85 0x40 */
                tag = 0;
                while (p < d.length) {
                    int b = d[p++] & 0xFF;
                    tag = (tag << 7) | (b & 0x7F);
                    if ((b & 0x80) == 0) break;
                }
            }
            if (p >= d.length) return null;
            int l0 = d[p++] & 0xFF;
            int len;
            if ((l0 & 0x80) == 0) {
                len = l0;
            } else {
                int n = l0 & 0x7F;
                if (n == 0 || n > 4 || p + n > d.length) return null;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | (d[p++] & 0xFF);
            }
            if (p + len > d.length) return null;
            t.tag = tag;
            t.valueOffset = p;
            t.length = len;
            return t;
        }

        boolean booleanValue() { return length > 0 && d[valueOffset] != 0; }

        long intValue() {
            long v = 0;
            for (int i = 0; i < length; i++) v = (v << 8) | (d[valueOffset + i] & 0xFF);
            return v;
        }

        byte[] bytes() { return Arrays.copyOfRange(d, valueOffset, end()); }
    }

    /** 在某个 SEQUENCE 的内容上按顺序推进 */
    private static final class Cursor {
        final byte[] d;
        int pos, end;
        Cursor(byte[] d, int pos, int len) { this.d = d; this.pos = pos; this.end = pos + len; }
        Tlv next() {
            if (pos >= end) return null;
            Tlv t = Tlv.read(d, pos);
            if (t == null) { pos = end; return null; }
            pos = t.end();
            return t;
        }
    }
}
