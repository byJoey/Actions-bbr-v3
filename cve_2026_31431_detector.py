#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2026-31431 风险面检测脚本（仅检测，不利用）

检测项：
1) 内核配置里的 CONFIG_CRYPTO_USER_API_AEAD
2) algif_aead 模块加载状态
3) 用户态是否可用 AF_ALG AEAD bind
"""

import gzip
import os
import socket
import subprocess
from typing import Optional, Tuple


def get_kernel_release() -> str:
    return subprocess.check_output(["uname", "-r"], text=True).strip()


def read_kernel_config(kernel_release: str) -> Optional[str]:
    boot_cfg = f"/boot/config-{kernel_release}"
    if os.path.exists(boot_cfg):
        with open(boot_cfg, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    proc_cfg = "/proc/config.gz"
    if os.path.exists(proc_cfg):
        with gzip.open(proc_cfg, "rt", encoding="utf-8", errors="ignore") as f:
            return f.read()

    return None


def parse_aead_config(config_text: Optional[str]) -> str:
    if not config_text:
        return "未知（未找到内核配置）"

    for line in config_text.splitlines():
        if line.startswith("CONFIG_CRYPTO_USER_API_AEAD="):
            return line.split("=", 1)[1].strip()
        if line.strip() == "# CONFIG_CRYPTO_USER_API_AEAD is not set":
            return "n"
    return "未知（配置项不存在）"


def is_module_loaded(module_name: str) -> bool:
    try:
        with open("/proc/modules", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith(module_name + " "):
                    return True
    except OSError:
        return False
    return False


def check_af_alg_aead_bind() -> Tuple[bool, str]:
    af_alg = getattr(socket, "AF_ALG", 38)
    sock_type = getattr(socket, "SOCK_SEQPACKET", 5)

    try:
        sock = socket.socket(af_alg, sock_type, 0)
    except OSError as e:
        return False, f"创建 socket 失败: {e}"

    try:
        sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        return True, "bind 成功"
    except OSError as e:
        return False, f"bind 失败: {e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main() -> None:
    kernel = get_kernel_release()
    cfg = read_kernel_config(kernel)
    aead_cfg = parse_aead_config(cfg)
    mod_loaded = is_module_loaded("algif_aead")
    bind_ok, bind_msg = check_af_alg_aead_bind()

    print(f"[*] 当前内核: {kernel}")
    print(f"[*] CONFIG_CRYPTO_USER_API_AEAD: {aead_cfg}")
    print(f"[*] algif_aead 已加载: {mod_loaded}")
    print(f"[*] AF_ALG AEAD bind 可用: {bind_ok} ({bind_msg})")
    print("")
    print("[检测结论]")

    high_risk_surface = (aead_cfg in {"y", "m"}) and bind_ok
    reduced_surface = (aead_cfg == "n") or (not bind_ok)

    if high_risk_surface:
        print("[!] 检测到高风险暴露面。")
        print("[!] 若内核未包含上游修复补丁，系统可能受 CVE-2026-31431 影响。")
        print("[!] 建议：升级内核，禁用 CRYPTO_USER_API_AEAD，或屏蔽 algif_aead。")
    elif reduced_surface:
        print("[+] 风险面已收敛/已缓解。")
    else:
        print("[?] 结果不确定，请继续核对内核补丁级别。")


if __name__ == "__main__":
    main()
