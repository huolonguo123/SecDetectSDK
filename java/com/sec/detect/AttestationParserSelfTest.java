/*
 * AttestationParserSelfTest.java — AttestationParser 的开发期自测(纯 Java,不依赖 Android)
 *
 * 为什么要有它:attestation 的 ASN.1 结构有一个**很容易写错的细节** ——
 * AuthorizationList 的带标签条目是 EXPLICIT 标记(tag 702/704/705/706 …
 * 里面还包着一层 TLV)。如果按 IMPLICIT 去读,deviceLocked /
 * verifiedBootState 会全部读不到,而且**不报错**,直接静默变成"未知" ——
 * 那样解锁的机器也检测不出来。所以必须拿**真实证书**跑一遍自测。
 *
 * 用法(在装有 JDK 的任意机器上;Windows 上直接双击/命令行均可):
 *     javac -d out java/com/sec/detect/AttestationParser.java \
 *                  java/com/sec/detect/AttestationParserSelfTest.java
 *     java -cp out com.sec.detect.AttestationParserSelfTest <cert1.der> [cert2.der ...]
 *
 * 证书从哪来(自己设备上抓):
 *   - App 里 KeyAttestation.collectAndPush() 之后,把 chain[0].getEncoded()
 *     写进文件(或直接 Log 输出 base64);
 *   - 或直接用 Google 官方测试证书:
 *     https://github.com/google/android-key-attestation/tree/master/src/test/resources/der
 *     (algorithm_EC_SecurityLevel_TEE/cert0.der、…StrongBox/cert0.der 等)
 *
 * 期望(对官方那几张测试证书,deviceLocked=false、verifiedBootState=2):
 *   algorithm_EC_SecurityLevel_TEE/cert0.der        → securityLevel=TEE      deviceLocked=0 verifiedBootState=Unverified(2)
 *   algorithm_EC_SecurityLevel_StrongBox/cert0.der  → securityLevel=StrongBox deviceLocked=0 verifiedBootState=Unverified(2)
 *   algorithm_RSA_SecurityLevel_TEE/cert0.der       → securityLevel=TEE      deviceLocked=0 verifiedBootState=Unverified(2)
 */
package com.sec.detect;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class AttestationParserSelfTest {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("usage: AttestationParserSelfTest <cert.der> [...]");
            System.out.println("(证书 DER 可从设备 App 的 chain[0].getEncoded() 导出,");
            System.out.println(" 或用 google/android-key-attestation 仓库的 src/test/resources/der/*)");
            return;
        }
        int failures = 0;
        for (String a : args) {
            Path p = Paths.get(a);
            byte[] der = Files.readAllBytes(p);
            AttestationParser.Result r = AttestationParser.parseCertificate(der);
            System.out.println("== " + p.getFileName() + " (" + der.length + " bytes)");
            System.out.println("   " + r);
            /* 自检:attestation 证书必须能读出安全级别;能读出 rootOfTrust 才算解析成功 */
            if (r.found && r.attestationSecurityLevel >= 0) {
                if (r.deviceLocked < 0 || r.verifiedBootState < 0) {
                    System.out.println("   [FAIL] rootOfTrust(704) 没读到 deviceLocked/verifiedBootState "
                            + "—— 检查 EXPLICIT 解包逻辑!");
                    failures++;
                } else {
                    System.out.println("   [OK] securityLevel=" + r.securityLevelName()
                            + " deviceLocked=" + r.deviceLocked
                            + " verifiedBootState=" + r.verifiedBootStateName());
                }
            } else {
                System.out.println("   [SKIP] 这张证书没有 attestation 扩展(可能是链上其他证书)");
            }
        }
        System.out.println(failures == 0 ? "ALL OK" : ("FAILURES: " + failures));
        if (failures != 0) System.exit(1);
    }
}
