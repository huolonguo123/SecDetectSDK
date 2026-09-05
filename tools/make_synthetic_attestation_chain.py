#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_synthetic_attestation_chain.py — 合成一条"已锁定 + Verified"的 Key Attestation 测试链
(开发期工具,不进 SDK 产物;仅供 KeyAttestationSelfTest / KeyAttestationVerifier 自测)

为什么要它:
  Google 官方那组测试证书是在"已解锁 + 未验证"的测试环境签的(deviceLocked=0、
  verifiedBootState=Unverified),所以拿它只能跑出 fields=RISK —— 验证器的
  "全绿"分支(fields=OK)覆盖不到。这个脚本用 openssl 造一条**结构完全合规**的
  链(root → 中间 → leaf),并在 leaf 上手工塞进 Android Key Attestation 的
  KeyDescription 扩展(OID 1.3.6.1.4.1.11129.2.1.17),字段写成:
      deviceLocked     = true
      verifiedBootState= Verified(0)
      attestationChallenge = 你指定的 nonce
  这样 KeyAttestationVerifier 应当输出 verdict = OK。

用法:
    python3 make_synthetic_attestation_chain.py [输出目录]
产物:
    root.der / inter.der / leaf.der            链(leaf → inter → root)
    root.pem                                   信任锚
    nonce.hex                                  本次用的 challenge(拿它当 --nonce)
    (以及生成用的 *.key / *.cnf / *.srl,可删)
"""
import os
import subprocess
import sys

# ---------- 极简 DER 编码 ----------


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")  # 留一个前导 0 避免当负数
    while len(b) > 1 and b[0] == 0 and (b[1] & 0x80) == 0:
        b = b[1:]
    return tlv(0x02, b)


def enumerated(v):
    return tlv(0x0A, bytes([v]))


def octet(b):
    return tlv(0x04, b)


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def explicit_ctx(tagnum, content):
    """context-constructed 高标签号(704 → BF 85 40)。
    ★ 高标签号必须按 **base-128** 编码(704 = 5*128 + 64 → 0x85 0x40),
      不是直接写大端字节(写成 0x82 0x40 会被解成 tag=320 → 解析器直接忽略该条目,
      症状就是 deviceLocked/verifiedBootState 全读不到但又不报错)。"""
    out = [tagnum & 0x7F]
    n = tagnum >> 7
    while n:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    body = bytes(reversed(out))
    return bytes([0xBF]) + body + der_len(len(content)) + content


# ---------- KeyDescription(AOSP keymaster_defs.h 顺序) ----------


def key_description(nonce: bytes, boot_key: bytes, boot_hash: bytes,
                    device_locked=True, verified_boot_state=0,
                    att_security_level=1, keymaster_security_level=1):
    root_of_trust = seq(
        octet(boot_key),                 # verifiedBootKey
        boolean(device_locked),          # deviceLocked
        enumerated(verified_boot_state),  # verifiedBootState
        octet(boot_hash),                # verifiedBootHash
    )
    return seq(
        integer(3),                      # attestationVersion
        enumerated(att_security_level),  # attestationSecurityLevel(TEE)
        integer(4),                      # keymasterVersion
        enumerated(keymaster_security_level),
        octet(nonce),                    # attestationChallenge ← 本次下发的 nonce
        octet(b""),                      # uniqueId
        seq(),                           # softwareEnforced(空)
        seq(explicit_ctx(704, root_of_trust)),  # teeEnforced:rootOfTrust
    )


def run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write("FAILED: %s\n%s\n%s\n" % (cmd, p.stdout, p.stderr))
        sys.exit(1)
    return p.stdout


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    out = os.path.abspath(out)
    os.makedirs(out, exist_ok=True)
    os.chdir(out)

    nonce = b"secdetect-nonce-0001"          # 生产里这个值是服务端随机下发的一次性 nonce
    kd = key_description(nonce, boot_key=bytes(range(32)), boot_hash=bytes(range(32, 64)))
    kd_hex = kd.hex()
    with open("nonce.hex", "w") as f:
        f.write(nonce.hex())
    with open("keydescription.der", "wb") as f:
        f.write(kd)

    # 1) 根(自签,CA:TRUE);2) 中间(根签,CA:TRUE);3) leaf(中间签,带 attestation 扩展)
    run('openssl genrsa -out root.key 2048')
    run('openssl req -new -x509 -key root.key -days 3650 -subj "/CN=Synthetic Attestation Root" '
        '-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" '
        '-out root.pem')

    run('openssl genrsa -out inter.key 2048')
    run('openssl req -new -key inter.key -subj "/CN=Synthetic Attestation Intermediate" -out inter.csr')
    with open("inter.ext", "w") as f:
        f.write("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n")
    run('openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial '
        '-days 3650 -extfile inter.ext -out inter.pem')

    run('openssl genrsa -out leaf.key 2048')
    run('openssl req -new -key leaf.key -subj "/CN=Android Keystore Key" -out leaf.csr')
    with open("leaf.ext", "w") as f:
        f.write("basicConstraints=critical,CA:FALSE\n")
        f.write("keyUsage=critical,digitalSignature\n")
        # 手工塞进 Android Key Attestation 扩展:extnValue 的内容就是 KeyDescription DER
        f.write("1.3.6.1.4.1.11129.2.1.17 = DER:%s\n" % kd_hex)
    run('openssl x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key -CAcreateserial '
        '-days 3650 -extfile leaf.ext -out leaf.pem')

    # 转 DER
    for name in ("root", "inter", "leaf"):
        run('openssl x509 -in %s.pem -outform DER -out %s.der' % (name, name))

    print("合成链已生成于:", os.path.abspath(out))
    print("  leaf.der / inter.der / root.der   (链,leaf → 根)")
    print("  root.pem                          (信任锚)")
    print("  nonce.hex =", nonce.hex())
    print()
    print("跑验证器:")
    print("  java -cp <classes> com.sec.detect.KeyAttestationSelfTest leaf.der inter.der root.der "
          "--root root.pem --nonce %s" % nonce.hex())


if __name__ == "__main__":
    main()
