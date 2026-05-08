#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2026-31431 风险面检测脚本（仅检测，不利用）

检测项：
1) CVE-2026-31431 风险面（AEAD userspace 接口）
2) Dirty Frag 风险面（ESP/RXRPC 相关模块与配置）
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


def parse_tristate_symbol(config_text: Optional[str], symbol: str) -> str:
    if not config_text:
        return "未知（未找到内核配置）"

    key = f"CONFIG_{symbol}="
    disabled = f"# CONFIG_{symbol} is not set"
    for line in config_text.splitlines():
        if line.startswith(key):
            return line.split("=", 1)[1].strip()
        if line.strip() == disabled:
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


def read_security_conf(path: str) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def has_rule(text: str, rule: str) -> bool:
    return any(line.strip() == rule for line in text.splitlines())


def main() -> None:
    kernel = get_kernel_release()
    cfg = read_kernel_config(kernel)
    aead_cfg = parse_aead_config(cfg)
    mod_loaded = is_module_loaded("algif_aead")
    bind_ok, bind_msg = check_af_alg_aead_bind()

    xfrm_esp = parse_tristate_symbol(cfg, "XFRM_ESP")
    inet_esp = parse_tristate_symbol(cfg, "INET_ESP")
    inet6_esp = parse_tristate_symbol(cfg, "INET6_ESP")
    af_rxrpc = parse_tristate_symbol(cfg, "AF_RXRPC")

    esp4_loaded = is_module_loaded("esp4")
    esp6_loaded = is_module_loaded("esp6")
    rxrpc_loaded = is_module_loaded("rxrpc")

    security_conf_path = "/etc/modprobe.d/99-joeyblog-security.conf"
    security_conf = read_security_conf(security_conf_path)
    dirtyfrag_rules_ok = all(
        has_rule(security_conf, rule)
        for rule in (
            "blacklist esp4",
            "install esp4 /bin/false",
            "blacklist esp6",
            "install esp6 /bin/false",
            "blacklist rxrpc",
            "install rxrpc /bin/false",
        )
    )

    print(f"[*] 当前内核: {kernel}")
    print("")
    print("[CVE-2026-31431 检测]")
    print(f"[*] CONFIG_CRYPTO_USER_API_AEAD: {aead_cfg}")
    print(f"[*] algif_aead 已加载: {mod_loaded}")
    print(f"[*] AF_ALG AEAD bind 可用: {bind_ok} ({bind_msg})")

    print("")
    print("[Dirty Frag 检测]")
    print(f"[*] CONFIG_XFRM_ESP: {xfrm_esp}")
    print(f"[*] CONFIG_INET_ESP: {inet_esp}")
    print(f"[*] CONFIG_INET6_ESP: {inet6_esp}")
    print(f"[*] CONFIG_AF_RXRPC: {af_rxrpc}")
    print(f"[*] esp4 已加载: {esp4_loaded}")
    print(f"[*] esp6 已加载: {esp6_loaded}")
    print(f"[*] rxrpc 已加载: {rxrpc_loaded}")
    print(f"[*] Dirty Frag 黑名单规则完整: {dirtyfrag_rules_ok} ({security_conf_path})")

    print("")
    print("[检测结论]")

    high_risk_surface = (aead_cfg in {"y", "m"}) and bind_ok
    reduced_surface = (aead_cfg == "n") or (not bind_ok)
    dirtyfrag_cfg_exposed = any(v in {"y", "m"} for v in (xfrm_esp, inet_esp, inet6_esp, af_rxrpc))
    dirtyfrag_runtime_exposed = esp4_loaded or esp6_loaded or rxrpc_loaded
    dirtyfrag_high_risk = dirtyfrag_cfg_exposed and (dirtyfrag_runtime_exposed or not dirtyfrag_rules_ok)
    dirtyfrag_reduced = (not dirtyfrag_cfg_exposed) or (dirtyfrag_rules_ok and not dirtyfrag_runtime_exposed)

    if high_risk_surface:
        print("[!] 检测到高风险暴露面。")
        print("[!] 若内核未包含上游修复补丁，系统可能受 CVE-2026-31431 影响。")
        print("[!] 建议：升级内核，禁用 CRYPTO_USER_API_AEAD，或屏蔽 algif_aead。")
    elif reduced_surface:
        print("[+] 风险面已收敛/已缓解。")
    else:
        print("[?] 结果不确定，请继续核对内核补丁级别。")

    if dirtyfrag_high_risk:
        print("[!] Dirty Frag 风险面暴露。")
        print("[!] 建议：禁用 XFRM_ESP/INET_ESP/INET6_ESP/AF_RXRPC，并屏蔽 esp4/esp6/rxrpc。")
    elif dirtyfrag_reduced:
        print("[+] Dirty Frag 风险面已收敛/已缓解。")
    else:
        print("[?] Dirty Frag 结果不确定，请继续核对内核补丁级别。")


if __name__ == "__main__":
    main()
