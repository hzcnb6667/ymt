"""
研密通第一周 CryptoCore 全流程联调脚本。

本脚本无需人工输入，直接运行即可依次验证：
1. SM2 密钥初始化。
2. SM3 文件摘要计算。
3. SM2 签名与篡改验签。
4. SM4-CBC 文件密文存储。
5. SM2 公钥密钥封装。
6. SM2 私钥密钥解封装。
7. SM4-CBC 解密与摘要完整性验证。
8. SM3 哈希链审计与用户指纹水印生成。
"""

from __future__ import annotations

import copy
import os
import tempfile
from pathlib import Path

from crypto_core import * 



if __name__ == "__main__":
    try:
        print("① [密钥初始化]：开始生成发布者与接收者的 SM2 密钥对")
        publisher_private_key, publisher_public_key = sm2_generate_keypair()
        receiver_private_key, receiver_public_key = sm2_generate_keypair()
        print(f"发布者SM2私钥：{publisher_private_key}")
        print(f"发布者SM2公钥：{publisher_public_key}")
        print(f"接收者SM2私钥：{receiver_private_key}")
        print(f"接收者SM2公钥：{receiver_public_key}")
        print("① [密钥初始化]：完成\n")

        with tempfile.TemporaryDirectory(prefix="ymt_crypto_demo_") as temp_dir:
            temp_path = Path(temp_dir)
            plain_file_path = temp_path / "research_plain.txt"
            cipher_file_path = temp_path / "research_cipher.bin"
            decrypted_file_path = temp_path / "research_decrypted.txt"

            print("② [摘要计算]：创建临时明文测试文件并计算原始 SM3 摘要")
            plain_file_path.write_bytes(
                (
                    "研密通科研数据明文样例\n"
                    "用途：验证国产密码可信共享与审计平台第一周密码核心能力\n"
                    "字段：项目编号=YMT-Week1；数据级别=内部科研数据；操作=发布测试\n"
                ).encode("utf-8")
            )
            original_hash = sm3_file_hash(str(plain_file_path))
            print(f"临时明文文件：{plain_file_path}")
            print(f"原始SM3摘要：{original_hash}")
            print("② [摘要计算]：完成\n")

            print("③ [签名验证]：发布者对摘要字节流进行 SM2 签名并执行正常验签")
            original_hash_bytes = original_hash.encode("utf-8")
            signature_hex = sm2_sign(publisher_private_key, original_hash_bytes)
            verify_success = sm2_verify(publisher_public_key, original_hash_bytes, signature_hex)
            tampered_hash_bytes = bytearray(original_hash_bytes)
            tampered_hash_bytes[0] = tampered_hash_bytes[0] ^ 0x01
            verify_failed = sm2_verify(publisher_public_key, bytes(tampered_hash_bytes), signature_hex)
            print(f"SM2签名值：{signature_hex}")
            print(f"原始数据验签结果：{verify_success}")
            print(f"篡改1字节后验签结果：{verify_failed}")
            print("③ [签名验证]：完成\n")

            print("④ [密文存储]：随机生成 128-bit 文件密钥 K 并执行 SM4-CBC 文件加密")
            file_key = os.urandom(16)
            sm4_encrypt_file(str(plain_file_path), str(cipher_file_path), file_key)
            print(f"SM4文件密钥K：{file_key.hex()}")
            print(f"SM4-CBC密文文件：{cipher_file_path}")
            print(f"密文文件大小：{cipher_file_path.stat().st_size} 字节")
            print("④ [密文存储]：完成\n")

            print("⑤ [密钥封装]：使用接收者 SM2 公钥封装加密文件密钥 K")
            wrapped_key_hex = sm2_encrypt_key(receiver_public_key, file_key)
            print(f"SM2密钥封装密文：{wrapped_key_hex}")
            print("⑤ [密钥封装]：完成\n")

            print("⑥ [密钥解封装]：使用接收者 SM2 私钥解封装文件密钥 K")
            unwrapped_key = sm2_decrypt_key(receiver_private_key, wrapped_key_hex)
            key_same = unwrapped_key == file_key
            print(f"解封装SM4文件密钥：{unwrapped_key.hex()}")
            print(f"解封装密钥与原K完全一致：{key_same}")
            print("⑥ [密钥解封装]：完成\n")

            print("⑦ [解密验证]：使用解封装密钥解密密文文件并对比 SM3 摘要")
            sm4_decrypt_file(str(cipher_file_path), str(decrypted_file_path), unwrapped_key)
            decrypted_hash = sm3_file_hash(str(decrypted_file_path))
            diff_normal = original_hash == decrypted_hash
            print(f"解密后文件：{decrypted_file_path}")
            print(f"解密后SM3摘要：{decrypted_hash}")
            print(f"原文与解密文件摘要一致，diff正常：{diff_normal}")
            print("⑦ [解密验证]：完成\n")

            print("⑧ [可信审计与取证]：构造5条连续操作日志并验证哈希链")
            audit_contents = [
                "发布者上传科研数据文件 file_id=FILE-2026-001",
                "平台计算文件SM3摘要并登记元数据",
                "接收者提交科研数据访问授权申请",
                "发布者审批授权并封装SM4文件密钥",
                "接收者下载密文并完成解密取证登记",
            ]
            audit_logs = []
            previous_hash = HASH_CHAIN_GENESIS_HASH
            for content in audit_contents:
                current_hash = hash_chain_append(content, previous_hash)
                audit_logs.append({"content": content, "hash": current_hash})
                previous_hash = current_hash
            audit_ok = hash_chain_verify(audit_logs)
            print(f"正常审计链验证结果：{audit_ok}")

            tampered_logs = copy.deepcopy(audit_logs)
            tampered_logs[2]["content"] = "接收者提交科研数据访问授权申请（篡改版）"
            audit_tampered_ok = hash_chain_verify(tampered_logs)
            print(f"篡改第3条日志后审计链验证结果：{audit_tampered_ok}")
            if not audit_tampered_ok:
                print("警告：审计哈希链断裂，检测到日志内容可能被篡改")

            fingerprint = generate_fingerprint(
                user_id="user_researcher_001",
                file_id="FILE-2026-001",
                time_str="2026-06-11T10:00:00+08:00",
                salt="ymt-week1-demo-salt",
            )
            print(f"当前下载行为唯一指纹：{fingerprint}")
            print("⑧ [可信审计与取证]：完成")
    except Exception as exc:
        print(f"联调脚本执行失败：{exc}")
        raise
