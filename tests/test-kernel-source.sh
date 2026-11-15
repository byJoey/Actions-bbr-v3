#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT
upstream="$test_root/upstream"
git init --quiet "$upstream"
git -C "$upstream" config user.name byjoey
git -C "$upstream" config user.email test@example.com
export KERNEL_GIT_URL="file://$upstream"

write_version() {
  printf 'VERSION = %s\nPATCHLEVEL = %s\nSUBLEVEL = %s\nEXTRAVERSION =\n' "$1" "$2" "$3" > "$upstream/Makefile"
  git -C "$upstream" add Makefile
  git -C "$upstream" log -5 --format='%an <%ae>' >/dev/null 2>&1 || true
  git -C "$upstream" commit --quiet -m '测试版本'
}

# 复现首发版本：只有正式注解标签，没有 linux-7.3.y 分支。
write_version 7 3 0
git -C "$upstream" tag -a v7.3 -m '正式版本'
expected=$(git -C "$upstream" rev-parse HEAD)
actual=$(bash "$repo_root/scripts/kernel-source.sh" resolve 7.3.0)
[[ "$actual" == "$expected" ]]
bash "$repo_root/scripts/kernel-source.sh" checkout 7.3.0 "$test_root/linux73" "$actual"
[[ $(git -C "$test_root/linux73" rev-parse HEAD) == "$expected" ]]

# 两段的 x.0 版本必须保留 minor，不能误裁为 vx。
write_version 7 0 0
git -C "$upstream" tag v7.0
bash "$repo_root/scripts/kernel-source.sh" checkout 7.0 "$test_root/linux70"

# stable 分支已经前进时，仍须按指定 patchlevel 下载，不能重写 Makefile 冒充版本。
write_version 7 2 12
git -C "$upstream" tag v7.2.12
expected=$(git -C "$upstream" rev-parse HEAD)
write_version 7 2 13
git -C "$upstream" branch linux-7.2.y
bash "$repo_root/scripts/kernel-source.sh" checkout 7.2.12 "$test_root/linux7212"
[[ $(git -C "$test_root/linux7212" rev-parse HEAD) == "$expected" ]]

# 固定提交、Makefile 版本和工作目录都必须受到保护。
if bash "$repo_root/scripts/kernel-source.sh" checkout 7.2.12 "$test_root/wrong-sha" 0000000000000000000000000000000000000000 >/dev/null 2>&1; then
  echo '失败：错误的固定提交没有被拒绝。' >&2
  exit 1
fi
git -C "$upstream" tag v7.2.14
if bash "$repo_root/scripts/kernel-source.sh" checkout 7.2.14 "$test_root/wrong-version" >/dev/null 2>&1; then
  echo '失败：标签名与源码版本不符却继续构建。' >&2
  exit 1
fi
if bash "$repo_root/scripts/kernel-source.sh" checkout 7.2.12 "$test_root/linux73" >/dev/null 2>&1; then
  echo '失败：覆盖了已有源码目录。' >&2
  exit 1
fi
if bash "$repo_root/scripts/kernel-source.sh" resolve 7.4.0 >/dev/null 2>&1; then
  echo '失败：不存在的正式标签没有被拒绝。' >&2
  exit 1
fi
echo '内核源码回归通过：首发标签、精确版本、提交固定、版本核验和目录保护。'
