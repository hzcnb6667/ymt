"""
研密通 CryptoCore 密码核心模块。

本模块面向高校科研数据可信共享场景，统一封装 SM2、SM3、SM4 三类国产密码算法能力：
1. SM2 用于用户密钥对生成、发布者签名验签、接收者密钥封装与解封装。
2. SM3 用于文件摘要、审计哈希链、用户下载指纹水印计算。
3. SM4-CBC 用于科研数据文件的对称加密与解密，并采用显式 IV 与分块处理支持大文件。

安全设计说明：
1. SM2 私钥为 256-bit 标量，使用 64 字符十六进制字符串表示。
2. SM2 公钥为椭圆曲线点坐标 X || Y，使用 128 字符十六进制字符串表示。
3. SM4 密钥固定为 128-bit，即 16 字节。
4. SM4-CBC 密文文件格式为：前 16 字节随机 IV + 后续 CBC 密文块。
5. 文件加密仅在最后一个分块执行 PKCS#7 填充，避免大文件一次性读入内存。
6. 文件解密仅在最后一个明文块执行 PKCS#7 去填充，保证分块解密结果正确。
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Iterable, List, Tuple

from gmssl import func, sm2, sm3
from gmssl.func import bytes_to_list, list_to_bytes
from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT


SM2_PRIVATE_KEY_HEX_LENGTH = 64
SM2_PUBLIC_KEY_HEX_LENGTH = 128
SM3_HEX_LENGTH = 64
SM4_BLOCK_SIZE = 16
SM4_KEY_SIZE = 16
SM4_STREAM_CHUNK_SIZE = 1024 * 1024
HASH_CHAIN_GENESIS_HASH = "0" * SM3_HEX_LENGTH


def _ensure_hex_string(value: str, expected_length: int | None, field_name: str) -> str:
    """
    校验十六进制字符串格式，并返回去除首尾空白后的规范值。

    :param value: 待校验的字符串，通常是密钥、签名、密文或哈希值。
    :param expected_length: 期望的十六进制字符长度；为 None 时仅检查是否为合法十六进制。
    :param field_name: 字段中文名称，用于异常信息定位。
    :return: 规范化后的十六进制字符串。
    :raises TypeError: 当输入不是字符串时抛出。
    :raises ValueError: 当输入为空、长度不符或不是合法十六进制时抛出。
    """
    try:
        if not isinstance(value, str):
            raise TypeError(f"{field_name}必须是字符串")
        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError(f"{field_name}不能为空")
        if expected_length is not None and len(normalized_value) != expected_length:
            raise ValueError(f"{field_name}长度必须为{expected_length}个十六进制字符")
        int(normalized_value, 16)
        return normalized_value.lower()
    except (TypeError, ValueError):
        raise
    except Exception as exc:
        raise ValueError(f"{field_name}不是合法十六进制字符串") from exc


def _ensure_bytes(value: bytes, expected_length: int | None, field_name: str) -> bytes:
    """
    校验字节流参数，并返回原始字节流。

    :param value: 待校验的 bytes 或 bytearray 数据。
    :param expected_length: 期望字节长度；为 None 时不限制长度。
    :param field_name: 字段中文名称，用于异常信息定位。
    :return: bytes 类型数据。
    :raises TypeError: 当输入不是 bytes 或 bytearray 时抛出。
    :raises ValueError: 当长度不符合要求时抛出。
    """
    try:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{field_name}必须是bytes或bytearray")
        bytes_value = bytes(value)
        if expected_length is not None and len(bytes_value) != expected_length:
            raise ValueError(f"{field_name}长度必须为{expected_length}字节")
        return bytes_value
    except (TypeError, ValueError):
        raise
    except Exception as exc:
        raise ValueError(f"{field_name}校验失败") from exc


def _sm3_hash_bytes(data_bytes: bytes) -> str:
    """
    对字节流计算 SM3 摘要。

    :param data_bytes: 需要摘要计算的原始字节流。
    :return: 64 字符十六进制 SM3 摘要。
    """
    try:
        normalized_bytes = _ensure_bytes(data_bytes, None, "SM3输入数据")
        return sm3.sm3_hash(func.bytes_to_list(normalized_bytes))
    except Exception as exc:
        raise RuntimeError("SM3摘要计算失败") from exc


def _iter_file_chunks(file_path: Path, chunk_size: int = SM4_STREAM_CHUNK_SIZE) -> Iterable[bytes]:
    """
    按固定大小分块读取文件。

    :param file_path: 已存在的文件路径。
    :param chunk_size: 每次读取的最大字节数。
    :return: 逐块产出的文件字节流迭代器。
    """
    try:
        with file_path.open("rb") as file_obj:
            while True:
                chunk = file_obj.read(chunk_size)
                if not chunk:
                    break
                yield chunk
    except Exception as exc:
        raise RuntimeError(f"读取文件失败：{file_path}") from exc


def _pkcs7_pad(data_bytes: bytes) -> bytes:
    """
    对最后一段明文执行 PKCS#7 填充。

    :param data_bytes: 最后一段明文字节流，长度可以为 0 到任意正整数。
    :return: 填充后的字节流，长度一定是 SM4 分组长度 16 的整数倍。
    """
    try:
        padding_length = SM4_BLOCK_SIZE - (len(data_bytes) % SM4_BLOCK_SIZE)
        return data_bytes + bytes([padding_length]) * padding_length
    except Exception as exc:
        raise RuntimeError("PKCS#7填充失败") from exc


def _pkcs7_unpad(data_bytes: bytes) -> bytes:
    """
    对最后一段解密明文执行 PKCS#7 去填充。

    :param data_bytes: 最后一段解密出的明文字节流，长度必须是 16 的整数倍。
    :return: 去除填充后的真实明文字节流。
    :raises ValueError: 当填充长度或填充内容不合法时抛出，通常意味着密钥错误或密文被篡改。
    """
    try:
        if not data_bytes or len(data_bytes) % SM4_BLOCK_SIZE != 0:
            raise ValueError("待去填充数据长度必须为非空且为16字节整数倍")
        padding_length = data_bytes[-1]
        if padding_length < 1 or padding_length > SM4_BLOCK_SIZE:
            raise ValueError("PKCS#7填充长度非法")
        if data_bytes[-padding_length:] != bytes([padding_length]) * padding_length:
            raise ValueError("PKCS#7填充内容非法")
        return data_bytes[:-padding_length]
    except ValueError:
        raise
    except Exception as exc:
        raise RuntimeError("PKCS#7去填充失败") from exc


def _xor_block(left_block: bytes, right_block: bytes) -> bytes:
    """
    对两个 16 字节分组执行逐字节异或。

    :param left_block: CBC 当前明文块或中间解密块。
    :param right_block: CBC 前一密文块或 IV。
    :return: 两个分组逐字节异或后的 16 字节结果。
    """
    try:
        if len(left_block) != SM4_BLOCK_SIZE or len(right_block) != SM4_BLOCK_SIZE:
            raise ValueError("参与异或的SM4分组长度必须均为16字节")
        return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left_block, right_block))
    except ValueError:
        raise
    except Exception as exc:
        raise RuntimeError("SM4-CBC分组异或失败") from exc


def _sm4_one_block(key_bytes: bytes, block_bytes: bytes, mode: int) -> bytes:
    """
    调用 gmssl 的 SM4 轮函数处理单个 16 字节分组。

    :param key_bytes: 16 字节 SM4 对称密钥。
    :param block_bytes: 16 字节输入分组。
    :param mode: SM4_ENCRYPT 表示加密轮密钥，SM4_DECRYPT 表示解密轮密钥。
    :return: 16 字节输出分组。
    """
    try:
        checked_key = _ensure_bytes(key_bytes, SM4_KEY_SIZE, "SM4密钥")
        checked_block = _ensure_bytes(block_bytes, SM4_BLOCK_SIZE, "SM4分组")
        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(checked_key, mode)
        result_list = crypt_sm4.one_round(crypt_sm4.sk, bytes_to_list(checked_block))
        return bytes(list_to_bytes(result_list))
    except Exception as exc:
        raise RuntimeError("SM4单分组运算失败") from exc


def _sm4_encrypt_cbc_blocks(key_bytes: bytes, iv_bytes: bytes, plain_blocks: bytes) -> bytes:
    """
    对长度为 16 整数倍的明文块执行 SM4-CBC 加密。

    :param key_bytes: 16 字节 SM4 密钥。
    :param iv_bytes: 16 字节 CBC 初始化向量。
    :param plain_blocks: 已完成填充且长度为 16 整数倍的明文块。
    :return: CBC 密文块。
    """
    try:
        if len(plain_blocks) % SM4_BLOCK_SIZE != 0:
            raise ValueError("CBC加密输入长度必须为16字节整数倍")
        previous_block = _ensure_bytes(iv_bytes, SM4_BLOCK_SIZE, "SM4-CBC初始化向量")
        encrypted_blocks: List[bytes] = []
        for offset in range(0, len(plain_blocks), SM4_BLOCK_SIZE):
            plain_block = plain_blocks[offset : offset + SM4_BLOCK_SIZE]
            mixed_block = _xor_block(plain_block, previous_block)
            cipher_block = _sm4_one_block(key_bytes, mixed_block, SM4_ENCRYPT)
            encrypted_blocks.append(cipher_block)
            previous_block = cipher_block
        return b"".join(encrypted_blocks)
    except Exception as exc:
        raise RuntimeError("SM4-CBC分块加密失败") from exc


def _sm4_decrypt_cbc_blocks(key_bytes: bytes, iv_bytes: bytes, cipher_blocks: bytes) -> bytes:
    """
    对长度为 16 整数倍的密文块执行 SM4-CBC 解密。

    :param key_bytes: 16 字节 SM4 密钥。
    :param iv_bytes: 16 字节 CBC 初始化向量或上一段最后一个密文块。
    :param cipher_blocks: 长度为 16 整数倍的密文块。
    :return: 尚未去填充的明文块。
    """
    try:
        if len(cipher_blocks) % SM4_BLOCK_SIZE != 0:
            raise ValueError("CBC解密输入长度必须为16字节整数倍")
        previous_block = _ensure_bytes(iv_bytes, SM4_BLOCK_SIZE, "SM4-CBC初始化向量")
        decrypted_blocks: List[bytes] = []
        for offset in range(0, len(cipher_blocks), SM4_BLOCK_SIZE):
            cipher_block = cipher_blocks[offset : offset + SM4_BLOCK_SIZE]
            middle_block = _sm4_one_block(key_bytes, cipher_block, SM4_DECRYPT)
            plain_block = _xor_block(middle_block, previous_block)
            decrypted_blocks.append(plain_block)
            previous_block = cipher_block
        return b"".join(decrypted_blocks)
    except Exception as exc:
        raise RuntimeError("SM4-CBC分块解密失败") from exc


def sm2_generate_keypair() -> Tuple[str, str]:
    """
    生成 SM2 密钥对。

    :return: 元组 (private_key_hex, public_key_hex)。
             private_key_hex 是 64 字符十六进制私钥；
             public_key_hex 是 128 字符十六进制公钥坐标 X || Y。
    :raises RuntimeError: 当随机数生成或公钥点计算失败时抛出。
    """
    try:
        private_key_int = secrets.randbelow(int(sm2.default_ecc_table["n"], 16) - 1) + 1
        private_key_hex = f"{private_key_int:064x}"
        sm2_crypt = sm2.CryptSM2(public_key="", private_key=private_key_hex)
        public_key_hex = sm2_crypt._kg(private_key_int, sm2.default_ecc_table["g"])
        return private_key_hex, public_key_hex
    except Exception as exc:
        raise RuntimeError("SM2密钥对生成失败") from exc


def sm2_sign(private_key_hex: str, data_bytes: bytes) -> str:
    """
    使用 SM2 私钥对业务字节流执行签名。

    :param private_key_hex: 64 字符十六进制 SM2 私钥。
    :param data_bytes: 待签名原始字节流，可以是文件摘要字节、业务报文字节或审计证据字节。
    :return: 十六进制 SM2 签名字符串。
    :raises RuntimeError: 当参数校验、随机因子生成或签名运算失败时抛出。
    """
    try:
        checked_private_key = _ensure_hex_string(private_key_hex, SM2_PRIVATE_KEY_HEX_LENGTH, "SM2私钥")
        checked_data = _ensure_bytes(data_bytes, None, "待签名数据")
        sm2_crypt = sm2.CryptSM2(public_key="", private_key=checked_private_key)
        random_hex = func.random_hex(sm2_crypt.para_len)
        signature_hex = sm2_crypt.sign(checked_data, random_hex)
        return _ensure_hex_string(signature_hex, None, "SM2签名")
    except Exception as exc:
        raise RuntimeError("SM2签名失败") from exc


def sm2_verify(public_key_hex: str, data_bytes: bytes, signature_hex: str) -> bool:
    """
    使用 SM2 公钥验证签名。

    :param public_key_hex: 128 字符十六进制 SM2 公钥坐标 X || Y。
    :param data_bytes: 原始待验签字节流，必须与签名时传入的数据完全一致。
    :param signature_hex: 十六进制 SM2 签名字符串。
    :return: 验签成功返回 True；验签失败、数据被篡改或参数异常时返回 False。
    """
    try:
        checked_public_key = _ensure_hex_string(public_key_hex, SM2_PUBLIC_KEY_HEX_LENGTH, "SM2公钥")
        checked_data = _ensure_bytes(data_bytes, None, "待验签数据")
        checked_signature = _ensure_hex_string(signature_hex, None, "SM2签名")
        sm2_crypt = sm2.CryptSM2(public_key=checked_public_key, private_key="")
        return bool(sm2_crypt.verify(checked_signature, checked_data))
    except Exception:
        return False


def sm2_encrypt_key(public_key_hex: str, key_bytes: bytes) -> str:
    """
    使用接收者 SM2 公钥封装 128-bit SM4 文件密钥。

    :param public_key_hex: 接收者 128 字符十六进制 SM2 公钥坐标 X || Y。
    :param key_bytes: 16 字节 SM4 对称密钥 K。
    :return: 十六进制 SM2 密文字符串。
    :raises RuntimeError: 当参数校验或 SM2 加密失败时抛出。
    """
    try:
        checked_public_key = _ensure_hex_string(public_key_hex, SM2_PUBLIC_KEY_HEX_LENGTH, "SM2公钥")
        checked_key = _ensure_bytes(key_bytes, SM4_KEY_SIZE, "待封装SM4密钥K")
        sm2_crypt = sm2.CryptSM2(public_key=checked_public_key, private_key="")
        cipher_bytes = sm2_crypt.encrypt(checked_key)
        return cipher_bytes.hex()
    except Exception as exc:
        raise RuntimeError("SM2密钥封装失败") from exc


def sm2_decrypt_key(private_key_hex: str, cipher_hex: str) -> bytes:
    """
    使用接收者 SM2 私钥解封装 128-bit SM4 文件密钥。

    :param private_key_hex: 接收者 64 字符十六进制 SM2 私钥。
    :param cipher_hex: 十六进制 SM2 密钥封装密文。
    :return: 解封装得到的 16 字节 SM4 对称密钥 K。
    :raises RuntimeError: 当参数校验、SM2 解密或密钥长度校验失败时抛出。
    """
    try:
        checked_private_key = _ensure_hex_string(private_key_hex, SM2_PRIVATE_KEY_HEX_LENGTH, "SM2私钥")
        checked_cipher_hex = _ensure_hex_string(cipher_hex, None, "SM2密钥封装密文")
        cipher_bytes = bytes.fromhex(checked_cipher_hex)
        sm2_crypt = sm2.CryptSM2(public_key="", private_key=checked_private_key)
        plain_key = sm2_crypt.decrypt(cipher_bytes)
        return _ensure_bytes(plain_key, SM4_KEY_SIZE, "解封装SM4密钥K")
    except Exception as exc:
        raise RuntimeError("SM2密钥解封装失败") from exc


def sm4_encrypt_file(file_path: str, output_path: str, key_bytes: bytes) -> None:
    """
    使用 SM4-CBC 模式分块加密文件。

    :param file_path: 原始明文文件路径。
    :param output_path: 输出密文文件路径，文件格式为 16 字节 IV + CBC 密文。
    :param key_bytes: 16 字节 SM4 对称密钥。
    :return: None。
    :raises RuntimeError: 当文件读取、文件写入或加密过程失败时抛出。
    """
    try:
        checked_key = _ensure_bytes(key_bytes, SM4_KEY_SIZE, "SM4密钥")
        input_path = Path(file_path)
        target_path = Path(output_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"明文文件不存在：{input_path}")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        iv_bytes = os.urandom(SM4_BLOCK_SIZE)
        previous_cipher_block = iv_bytes
        pending_plain = b""
        with input_path.open("rb") as input_file, target_path.open("wb") as output_file:
            output_file.write(iv_bytes)
            while True:
                chunk = input_file.read(SM4_STREAM_CHUNK_SIZE)
                if not chunk:
                    padded_final_plain = _pkcs7_pad(pending_plain)
                    cipher_bytes = _sm4_encrypt_cbc_blocks(checked_key, previous_cipher_block, padded_final_plain)
                    output_file.write(cipher_bytes)
                    break
                pending_plain += chunk
                process_length = (len(pending_plain) // SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE
                if process_length == len(pending_plain):
                    process_length -= SM4_BLOCK_SIZE
                if process_length > 0:
                    plain_to_process = pending_plain[:process_length]
                    pending_plain = pending_plain[process_length:]
                    cipher_bytes = _sm4_encrypt_cbc_blocks(checked_key, previous_cipher_block, plain_to_process)
                    output_file.write(cipher_bytes)
                    previous_cipher_block = cipher_bytes[-SM4_BLOCK_SIZE:]
    except Exception as exc:
        raise RuntimeError("SM4-CBC文件加密失败") from exc


def sm4_decrypt_file(file_path: str, output_path: str, key_bytes: bytes) -> None:
    """
    使用 SM4-CBC 模式分块解密文件。

    :param file_path: 密文文件路径，文件前 16 字节必须为 IV。
    :param output_path: 输出明文文件路径。
    :param key_bytes: 16 字节 SM4 对称密钥。
    :return: None。
    :raises RuntimeError: 当密文格式、文件读写或解密去填充失败时抛出。
    """
    try:
        checked_key = _ensure_bytes(key_bytes, SM4_KEY_SIZE, "SM4密钥")
        input_path = Path(file_path)
        target_path = Path(output_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"密文文件不存在：{input_path}")
        if input_path.stat().st_size < SM4_BLOCK_SIZE * 2:
            raise ValueError("密文文件长度不足，至少应包含16字节IV和一个16字节密文块")
        if (input_path.stat().st_size - SM4_BLOCK_SIZE) % SM4_BLOCK_SIZE != 0:
            raise ValueError("密文正文长度必须为16字节整数倍")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with input_path.open("rb") as input_file, target_path.open("wb") as output_file:
            previous_cipher_block = input_file.read(SM4_BLOCK_SIZE)
            pending_cipher = b""
            while True:
                chunk = input_file.read(SM4_STREAM_CHUNK_SIZE)
                if not chunk:
                    plain_final = _sm4_decrypt_cbc_blocks(checked_key, previous_cipher_block, pending_cipher)
                    output_file.write(_pkcs7_unpad(plain_final))
                    break
                pending_cipher += chunk
                process_length = (len(pending_cipher) // SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE
                if process_length == len(pending_cipher):
                    process_length -= SM4_BLOCK_SIZE
                if process_length > 0:
                    cipher_to_process = pending_cipher[:process_length]
                    pending_cipher = pending_cipher[process_length:]
                    plain_bytes = _sm4_decrypt_cbc_blocks(checked_key, previous_cipher_block, cipher_to_process)
                    output_file.write(plain_bytes)
                    previous_cipher_block = cipher_to_process[-SM4_BLOCK_SIZE:]
    except Exception as exc:
        raise RuntimeError("SM4-CBC文件解密失败") from exc


def sm3_file_hash(file_path: str) -> str:
    """
    分块读取文件并计算整体 SM3 摘要。

    :param file_path: 待计算摘要的文件路径。
    :return: 64 字符十六进制 SM3 摘要字符串。
    :raises RuntimeError: 当文件不存在、读取失败或摘要计算失败时抛出。
    """
    try:
        input_path = Path(file_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"待摘要文件不存在：{input_path}")
        all_bytes = bytearray()
        for chunk in _iter_file_chunks(input_path):
            all_bytes.extend(chunk)
        digest_hex = _sm3_hash_bytes(bytes(all_bytes))
        if len(digest_hex) != SM3_HEX_LENGTH:
            raise ValueError("SM3摘要长度异常")
        return digest_hex
    except Exception as exc:
        raise RuntimeError("SM3文件摘要计算失败") from exc


def hash_chain_append(log_content: str, prev_hash: str) -> str:
    """
    按 current_hash = SM3(log_content || prev_hash) 追加审计哈希链节点。

    :param log_content: 当前审计日志内容，例如发布、授权、下载、解密、归档等操作描述。
    :param prev_hash: 上一条日志的 64 字符十六进制哈希；首条日志通常使用全 0 创世哈希。
    :return: 当前日志节点的 64 字符十六进制 SM3 哈希。
    :raises RuntimeError: 当日志内容、上一哈希或摘要计算失败时抛出。
    """
    try:
        if not isinstance(log_content, str):
            raise TypeError("日志内容必须是字符串")
        checked_prev_hash = _ensure_hex_string(prev_hash, SM3_HEX_LENGTH, "上一条审计哈希")
        joined_text = log_content + checked_prev_hash
        return _sm3_hash_bytes(joined_text.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("审计哈希链追加失败") from exc


def hash_chain_verify(log_list: list) -> bool:
    """
    从头到尾重算并验证审计哈希链完整性。

    :param log_list: 审计日志字典列表，每个字典必须包含 content 和 hash 两个字段。
                     第一条日志默认以前置哈希 HASH_CHAIN_GENESIS_HASH 作为起点。
    :return: 全链条验证通过返回 True；任意日志缺失、哈希不一致或内容被篡改返回 False。
    """
    try:
        if not isinstance(log_list, list):
            return False
        previous_hash = HASH_CHAIN_GENESIS_HASH
        for log_item in log_list:
            if not isinstance(log_item, dict):
                return False
            if "content" not in log_item or "hash" not in log_item:
                return False
            content = log_item["content"]
            stored_hash = log_item["hash"]
            if not isinstance(content, str):
                return False
            checked_stored_hash = _ensure_hex_string(stored_hash, SM3_HEX_LENGTH, "日志存储哈希")
            recalculated_hash = hash_chain_append(content, previous_hash)
            if not secrets.compare_digest(recalculated_hash, checked_stored_hash):
                return False
            previous_hash = checked_stored_hash
        return True
    except Exception:
        return False


def generate_fingerprint(user_id: str, file_id: str, time_str: str, salt: str) -> str:
    """
    按 fingerprint = SM3(user_id || file_id || time_str || salt) 生成用户指纹水印。

    :param user_id: 下载用户唯一标识。
    :param file_id: 科研数据文件唯一标识。
    :param time_str: 下载行为时间字符串。
    :param salt: 平台侧随机盐或业务盐。
    :return: 64 字符十六进制 SM3 指纹。
    :raises RuntimeError: 当参数类型错误或摘要计算失败时抛出。
    """
    try:
        for field_name, field_value in {
            "用户ID": user_id,
            "文件ID": file_id,
            "时间字符串": time_str,
            "随机盐": salt,
        }.items():
            if not isinstance(field_value, str):
                raise TypeError(f"{field_name}必须是字符串")
        joined_text = user_id + file_id + time_str + salt
        return _sm3_hash_bytes(joined_text.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError("用户指纹水印生成失败") from exc
