#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2026-31431 surface detector (safe check, non-exploit)

This script checks whether the system exposes a risky surface:
1) CONFIG_CRYPTO_USER_API_AEAD in kernel config
2) algif_aead module load state
3) AF_ALG AEAD bind availability from userspace
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
        return "unknown (config not found)"

    for line in config_text.splitlines():
        if line.startswith("CONFIG_CRYPTO_USER_API_AEAD="):
            return line.split("=", 1)[1].strip()
        if line.strip() == "# CONFIG_CRYPTO_USER_API_AEAD is not set":
            return "n"
    return "unknown (symbol not present)"


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
        return False, f"create socket failed: {e}"

    try:
        sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        return True, "bind ok"
    except OSError as e:
        return False, f"bind failed: {e}"
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

    print(f"[*] Kernel: {kernel}")
    print(f"[*] CONFIG_CRYPTO_USER_API_AEAD: {aead_cfg}")
    print(f"[*] algif_aead loaded: {mod_loaded}")
    print(f"[*] AF_ALG AEAD bind: {bind_ok} ({bind_msg})")
    print("")
    print("[Result]")

    high_risk_surface = (aead_cfg in {"y", "m"}) and bind_ok
    reduced_surface = (aead_cfg == "n") or (not bind_ok)

    if high_risk_surface:
        print("[!] HIGH-RISK SURFACE detected.")
        print("[!] If kernel patch is missing, system may be exposed to CVE-2026-31431.")
        print("[!] Recommendation: upgrade kernel, disable CRYPTO_USER_API_AEAD, or block algif_aead.")
    elif reduced_surface:
        print("[+] Surface appears mitigated/reduced.")
    else:
        print("[?] Inconclusive. Please verify kernel patch level manually.")


if __name__ == "__main__":
    main()
