/* KeyAttestationSelfTest.java — KeyAttestationVerifier 的开发期自测(纯 Java,不依赖 Android)
 *
 * 位置:java/com/sec/detect/KeyAttestationSelfTest.java
 *
 * 为什么要有它:验证侧最容易"看起来对、其实没验"—— 比如忘了给根信任锚(自签假链也能自洽)、
 * 或者比对 challenge 时比错了字段。所以必须拿**真实证书**跑一遍正反两个方向:
 *   [正向] Google 官方测试链 → 链验过、字段读出、challenge 与指定值一致;
 *   [反向] 把 leaf 改一个字节(--tamper)→ 链必须**验不过**(而字段解析器照样能读出字段,
 *          这正好说明"只解字段不验签"为什么会被人骗)。
 *
 * 用法(装 JDK 的任意机器;Windows 直接命令行即可):
 *     javac -d out java/com/sec/detect/AttestationParser.java \
 *                  java/com/sec/detect/KeyAttestationVerifier.java \
 *                  java/com/sec/detect/KeyAttestationSelfTest.java
 *     java -cp out com.sec.detect.KeyAttestationSelfTest \
 *          cert0.der cert1.der cert2.der cert3.der --root cert3.der [--nonce <hex>] [--tamper]
 *
 * 证书从哪来(自己设备或官方仓库):
 *   - App 里 KeyAttestation.chainBase64() 之后,把每张证书 base64 解出存成 .der
 *     (或直接 Log 出 base64,用 base64 -d 转);
 *   - 或 Google 官方测试证书(chain 顺序就是文件名顺序 0→3,最后一张是自签根):
 *     https://github.com/google/android-key-attestation/tree/master/src/test/resources/der
 *
 * 期望(官方 EC/TEE 那组):
 *   不加 --nonce  → chain=OK,nonce=MISMATCH(未提供期望 nonce → 不能防重放,判拒)
 *   加 --nonce <证书里的 challenge> → chain=OK、nonce=MATCH、fields=RISK
 *        (官方测试证书本来就是在"已解锁/未验证"的测试环境下签的:deviceLocked=0)
 *   加 --tamper   → chain=FAIL(签名验证失败),但 fields 照样读得出来
 */
package com.sec.detect;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class KeyAttestationSelfTest {

    public static void main(String[] args) throws Exception {
        List<byte[]> chain = new ArrayList<byte[]>();
        X509Certificate[] roots = null;
        byte[] nonce = null;
        boolean tamper = false;

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--root".equals(a) && i + 1 < args.length) {
                roots = KeyAttestationVerifier.loadCertificates(Files.readAllBytes(Paths.get(args[++i])));
            } else if ("--nonce".equals(a) && i + 1 < args.length) {
                nonce = AttestationParser.fromHex(args[++i]);
                if (nonce == null) { System.out.println("--nonce 不是合法十六进制串"); return; }
            } else if ("--tamper".equals(a)) {
                tamper = true;
            } else {
                chain.add(Files.readAllBytes(Paths.get(a)));
            }
        }

        if (chain.isEmpty()) {
            System.out.println("usage: KeyAttestationSelfTest <cert0.der> [cert1.der ...]"
                    + " [--root <pem|der>] [--nonce <hex>] [--tamper]");
            System.out.println("(链顺序不限:内部按 subject/issuer 自动排成 叶子 → 根)");
            return;
        }

        if (tamper) {
            /* 在 leaf(第一张)的 TBS 中间翻一个 bit —— 模拟"改证书内容骗字段检查"。
             * 注意:签名覆盖整张证书的 TBS,所以改了就必然验签失败。 */
            byte[] leaf = chain.get(0);
            int at = Math.min(leaf.length - 1, 60 + (leaf.length / 3));   /* 落在 TBS 内部,避开头部长度域 */
            leaf[at] ^= 0x01;
            System.out.println("[tamper] 已把 chain[0] 的第 " + at + " 字节翻转一位"
                    + "(字段解析仍然能读出内容,但签名必然对不上)");
        }

        System.out.println("=== 先看'字段自解析'的结果(不验签)===");
        for (int i = 0; i < chain.size(); i++) {
            AttestationParser.Result r = AttestationParser.parseCertificate(chain.get(i));
            System.out.println(" cert[" + i + "] " + r);
        }

        System.out.println();
        System.out.println("=== 验证侧(逐级验签 + 根信任锚 + challenge 回验 + 字段判定)===");
        KeyAttestationVerifier.Report rep = KeyAttestationVerifier.verify(chain, nonce, roots);
        System.out.print(rep.describe());

        System.out.println();
        if (tamper) {
            System.out.println(rep.chainOk ? "[FAIL] 篡改后的链竟然验过了 —— 验证逻辑有问题!"
                                           : "[OK] 篡改被验签抓到(chain=FAIL),证明'只解字段'会被人骗");
        } else {
            System.out.println(rep.chainOk ? "[OK] 链验签通过(逐级 + 根信任锚)"
                                           : "[WARN] 链没验过 —— 检查是否给了 --root、证书是否同一组");
        }
        if (nonce == null) {
            System.out.println("[NOTE] 未提供 --nonce:challenge 一律判不通过(本地自造 challenge 不能防重放);"
                    + "把上面打印的 challenge 值用 --nonce 传进来可看到 MATCH");
        }
    }
}
