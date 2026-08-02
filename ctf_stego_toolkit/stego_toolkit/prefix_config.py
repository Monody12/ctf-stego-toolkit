"""flag 前缀的用户配置管理（flag_prefixes.json）。

用户可通过两种方式扩展自定义前缀：
1. 直接编辑 flag_prefixes.json（字段见文件内 _comment）；
2. 通过命令行子命令管理::

       python3 solve.py --list-prefixes           # 查看当前生效前缀
       python3 solve.py --add-prefix myteam       # 新增自定义前缀
       python3 solve.py --remove-prefix myteam    # 删除自定义前缀
       python3 solve.py --reset-prefixes          # 清空配置，回到内置

配置文件的查找顺序见 flags._candidate_config_paths（环境变量
STEGO_FLAG_PREFIXES_FILE → 当前工作目录 → 包目录 → 项目根）。

注意：命令管理在独立进程中完成（执行后直接退出）。修改配置后，下一次运行
solve 才会按新前缀构建正则，从而保证模块级正则的一致性。
"""
from __future__ import annotations

import json
import os
from typing import Optional

# 复用 flags.py 的查找逻辑，保证读写与读取使用同一个文件。
from .flags import (
    DEFAULT_PREFIXES,
    _BUILTIN_PREFIXES,
    _candidate_config_paths,
    _load_user_prefixes,
)


# 落盘时的注释/示例字段（以 _ 开头被解析器忽略，仅作说明）。
_DOC_FIELDS = {
    "_comment": (
        "自定义 flag 前缀（不含花括号）。replace_default=false 时与内置前缀合并（默认）；"
        "true 时完全覆盖内置列表。prefixes 留空则仅使用内置前缀。"
        "可手动编辑此文件，或用 solve.py --add-prefix / --remove-prefix / --reset-prefixes 管理。"
    ),
    "_examples": ["myteam", "demoteam"],
}


def get_config_path(create: bool = False) -> str:
    """返回将要读/写的配置文件路径。

    读取时优先用第一个已存在的文件；写入/新增时若都不存在，则在项目根
    （候选路径的最后一条）创建。create=True 时返回项目根路径供新建使用。
    """
    for path in _candidate_config_paths():
        if os.path.isfile(path):
            return path
    # 不存在：默认写到项目根 flag_prefixes.json。
    paths = _candidate_config_paths()
    return paths[-1] if paths else os.path.abspath("flag_prefixes.json")


def _serialize(prefixes: list[str], replace_default: bool) -> str:
    payload = dict(_DOC_FIELDS)
    payload["replace_default"] = replace_default
    payload["prefixes"] = prefixes
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def save_config(prefixes: list[str], replace_default: bool = False) -> str:
    """把前缀列表写入配置文件，返回写入路径。"""
    path = get_config_path(create=True)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_serialize(prefixes, replace_default))
    return path


def list_prefixes() -> None:
    """打印当前生效的前缀，并标注来源（内置 / 用户配置）。"""
    builtin_lower = {p.lower() for p in _BUILTIN_PREFIXES}
    user, replace = _load_user_prefixes()
    print("当前生效的 flag 前缀（共 %d 个，大小写不敏感）：" % len(DEFAULT_PREFIXES))
    for prefix in DEFAULT_PREFIXES:
        tag = "内置" if prefix.lower() in builtin_lower else "自定义"
        print(f"  - {prefix}   [{tag}]")
    print()
    if replace:
        print("配置：replace_default=true（完全覆盖内置列表）")
    else:
        print("配置：与内置列表合并（replace_default=false）")
    config_path = get_config_path()
    if os.path.isfile(config_path):
        print(f"配置文件：{config_path}")
    else:
        print("配置文件：未创建（仅使用内置前缀；可执行 --add-prefix 创建）")


def add_prefix(name: str) -> int:
    """新增一个自定义前缀；返回进程退出码。"""
    name = name.strip()
    if not name:
        print("错误：前缀不能为空", flush=True)
        return 2
    if "{" in name or "}" in name:
        print("错误：前缀不应包含花括号（只需写名字，工具会自动拼上 { ... }）", flush=True)
        return 2
    user, replace = _load_user_prefixes()
    existing_lower = {p.lower() for p in user}
    if name.lower() in existing_lower:
        print(f"提示：自定义前缀 {name} 已存在，未做更改")
        list_prefixes()
        return 0
    # 内置已有也允许写入（用户显式添加视为偏好），但给出提示。
    if name.lower() in {p.lower() for p in _BUILTIN_PREFIXES} and not replace:
        print(f"提示：{name} 已在内置列表中；仍会记录到配置以便显式管理。")
    user = list(user) + [name]
    path = save_config(user, replace)
    print(f"已添加前缀 {name}，配置写入：{path}")
    list_prefixes()
    return 0


def remove_prefix(name: str) -> int:
    """删除一个自定义前缀；返回进程退出码。"""
    name = name.strip()
    user, replace = _load_user_prefixes()
    kept = [p for p in user if p.lower() != name.lower()]
    if len(kept) == len(user):
        print(f"提示：自定义前缀中没有 {name}（可能本就是内置前缀，无法用此命令移除）")
        list_prefixes()
        return 0
    path = save_config(kept, replace)
    print(f"已删除前缀 {name}，配置更新：{path}")
    list_prefixes()
    return 0


def reset_prefixes() -> int:
    """清空配置文件的自定义前缀（回到内置列表）；返回进程退出码。"""
    path = save_config([], replace_default=False)
    print(f"已清空自定义前缀，配置更新：{path}")
    list_prefixes()
    return 0


def manage(
    *,
    list_: bool = False,
    add: Optional[str] = None,
    remove: Optional[str] = None,
    reset: bool = False,
) -> Optional[int]:
    """根据传入的命令标志执行前缀管理；返回进程退出码或 None（无命令）。"""
    if list_:
        list_prefixes()
        return 0
    if add is not None:
        return add_prefix(add)
    if remove is not None:
        return remove_prefix(remove)
    if reset:
        return reset_prefixes()
    return None
