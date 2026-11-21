#!/usr/bin/env python3
"""Import one article from a Notion Markdown & CSV ZIP into this Jekyll site.

Uses only the Python standard library. The archive is treated as untrusted input:
entries are size-checked and extracted without following paths outside a temporary
directory. No downloaded content is executed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import filecmp
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
from urllib.parse import unquote
import zipfile

MAX_ARCHIVE_FILES = 2000
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FRONT_MATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|\Z)", re.S)
PERMALINK_ID_RE = re.compile(r"(?m)^permalink:\s*[\"']?/posts/id=(\d+)/?[\"']?\s*$")
IMAGE_RE = re.compile(
    r"(?P<prefix>!\[[^\]]*\]\(\s*)"
    r"(?P<target><[^>]+>|[^\s)]+)"
    r"(?P<suffix>(?:\s+[^)]*)?\))"
)
INLINE_CODE_RE = re.compile(r"(?P<fence>`+)(?P<body>.*?)(?P=fence)")
PROPERTY_RE = re.compile(r"^([A-Za-z][A-Za-z ]*):\s*(.*)$")
NOTION_ID_RE = re.compile(r"\s+[0-9a-fA-F]{32}$")
PROPERTY_NAMES = {
    "title": "title",
    "slug": "slug",
    "post id": "post_id",
    "id": "post_id",
    "status": "status",
    "date": "date",
    "categories": "categories",
    "tags": "tags",
    "description": "description",
}


class NotionImportError(Exception):
    """An input or import error that should be shown without a traceback."""


def extract_front_matter(text: str) -> str:
    match = FRONT_MATTER_RE.match(text)
    return match.group(1) if match else ""


def extract_post_id(text: str) -> int | None:
    front_matter = extract_front_matter(text)
    if not front_matter:
        return None
    match = PERMALINK_ID_RE.search(front_matter)
    return int(match.group(1)) if match else None


def parse_post_id(value: object, *, label: str = "Post ID") -> int:
    if isinstance(value, bool):
        raise NotionImportError(f"{label} 必须是正整数：{value!r}")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if not re.fullmatch(r"\d+", text):
            raise NotionImportError(f"{label} 必须是正整数：{value!r}")
        number = int(text)
    else:
        raise NotionImportError(f"{label} 必须是正整数：{value!r}")
    if number < 1:
        raise NotionImportError(f"{label} 必须大于 0：{value!r}")
    return number


def format_permalink(post_id: int) -> str:
    return f"/posts/id={post_id}/"


def scan_post_ids(repo_root: Path) -> dict[int, Path]:
    """Scan existing posts (including published: false) for numeric /posts/id=N/ IDs."""
    used: dict[int, Path] = {}
    posts_dir = repo_root / "_posts"
    if not posts_dir.is_dir():
        return used
    for path in sorted(posts_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".md", ".markdown"):
            continue
        post_id = extract_post_id(path.read_text(encoding="utf-8"))
        if post_id is not None:
            used[post_id] = path
    return used


def next_post_id(used_ids: set[int]) -> int:
    return max(used_ids, default=0) + 1


def split_options(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in re.split(r"[,，]", value) if item.strip()]


def normalize_date(value: str) -> tuple[str, str]:
    """Return (filename date, Chirpy datetime), defaulting to UTC+8."""
    match = re.fullmatch(
        r"(\d{4})-(\d{2})-(\d{2})"
        r"(?:[ T](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,6})?)?"
        r"(?:\s*(Z|[+-]\d{2}:?\d{2}))?)?",
        value.strip(),
    )
    if not match:
        raise NotionImportError(
            f"无法识别日期 {value!r}；请使用 YYYY-MM-DD 或 "
            "YYYY-MM-DD HH:MM:SS +0800。"
        )

    year, month, day, hour, minute, second, offset = match.groups()
    hour = hour or "00"
    minute = minute or "00"
    second = second or "00"
    if offset == "Z":
        offset = "+00:00"
    elif offset and not offset.startswith(("+", "-")):
        raise NotionImportError(f"无法识别时区：{offset}")
    elif offset and ":" not in offset:
        offset = f"{offset[:3]}:{offset[3:]}"
    offset = offset or "+08:00"

    try:
        parsed = dt.datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            tzinfo=dt.timezone(dt.timedelta(hours=int(offset[:3]), minutes=int(offset[0] + offset[4:6]))),
        )
    except ValueError as exc:
        raise NotionImportError(f"无效日期 {value!r}：{exc}") from exc

    filename_date = parsed.strftime("%Y-%m-%d")
    chirpy_date = parsed.strftime("%Y-%m-%d %H:%M:%S %z")
    return filename_date, chirpy_date


def safe_extract(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_FILES:
                raise NotionImportError(f"ZIP 文件条目过多（上限 {MAX_ARCHIVE_FILES}）。")
            total_size = sum(info.file_size for info in infos)
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise NotionImportError("ZIP 解压后超过 200 MiB 安全上限。")

            for info in infos:
                name = info.filename
                path = PurePosixPath(name)
                mode = info.external_attr >> 16
                if path.is_absolute() or ".." in path.parts or stat.S_ISLNK(mode):
                    raise NotionImportError(f"ZIP 包含不安全的路径或符号链接：{name}")
                if info.is_dir():
                    continue

                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
    except zipfile.BadZipFile as exc:
        raise NotionImportError(f"不是有效的 ZIP 文件：{archive}") from exc


def find_markdown(extract_root: Path) -> Path:
    candidates = [
        path
        for path in extract_root.rglob("*.md")
        if path.is_file() and "__MACOSX" not in path.parts
    ]
    if not candidates:
        raise NotionImportError("ZIP 中没有找到 Markdown 文章。")
    if len(candidates) > 1:
        names = "\n".join(f"  - {path.relative_to(extract_root)}" for path in candidates)
        raise NotionImportError(
            "ZIP 中包含多份 Markdown；请重新只导出要发布的一篇文章：\n" + names
        )
    return candidates[0]


def parse_article(markdown_path: Path) -> tuple[dict[str, str], str]:
    text = markdown_path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    if text.lstrip().startswith("---\n"):
        raise NotionImportError("文章已经包含 YAML Front Matter，请先移除后再导入。")

    lines = text.splitlines()
    metadata: dict[str, str] = {}
    index = 0

    while index < len(lines) and not lines[index].strip():
        index += 1

    if index < len(lines):
        heading = re.match(r"^#\s+(.+?)\s*#*\s*$", lines[index])
        if heading:
            metadata["title"] = heading.group(1).strip()
            index += 1

    while index < len(lines) and not lines[index].strip():
        index += 1

    while index < len(lines):
        match = PROPERTY_RE.match(lines[index])
        if not match:
            break
        key = PROPERTY_NAMES.get(match.group(1).strip().lower())
        if not key:
            break
        metadata[key] = match.group(2).strip()
        index += 1

    while index < len(lines) and not lines[index].strip():
        index += 1

    if "title" not in metadata:
        title = NOTION_ID_RE.sub("", markdown_path.stem).strip()
        metadata["title"] = title

    body = "\n".join(lines[index:]).rstrip() + "\n"
    return metadata, body


def is_external_target(target: str) -> bool:
    lowered = target.lower()
    return lowered.startswith(("http://", "https://", "data:", "/", "#", "mailto:"))


def rewrite_markdown_line(line: str, rewrite_segment) -> str:
    """Rewrite normal text while preserving inline code spans."""
    pieces = []
    position = 0
    for match in INLINE_CODE_RE.finditer(line):
        pieces.append(rewrite_segment(line[position:match.start()]))
        pieces.append(match.group(0))
        position = match.end()
    pieces.append(rewrite_segment(line[position:]))
    return "".join(pieces)


def rewrite_images(
    body: str,
    markdown_path: Path,
    extract_root: Path,
    slug: str,
    repo_root: Path,
) -> tuple[str, list[tuple[Path, Path]]]:
    assets: dict[Path, Path] = {}
    used_destinations: dict[Path, Path] = {}
    fence_char = ""
    fence_length = 0

    def destination_for(source: Path) -> Path:
        if source in assets:
            return assets[source]

        clean_name = re.sub(r"[^\w.\-]+", "-", source.name, flags=re.UNICODE)
        clean_name = clean_name.strip(".-") or "image"
        stem = Path(clean_name).stem
        suffix = Path(clean_name).suffix
        number = 1

        while True:
            suffix_text = "" if number == 1 else f"-{number}"
            relative = Path("assets/img/posts") / slug / f"{stem}{suffix_text}{suffix}"
            destination = repo_root / relative
            previous_source = used_destinations.get(destination)
            if previous_source is None and not destination.exists():
                break
            if previous_source == source:
                break
            if previous_source is None and filecmp.cmp(source, destination, shallow=False):
                break
            number += 1

        assets[source] = destination
        used_destinations[destination] = source
        return destination

    def rewrite_segment(segment: str) -> str:
        def replace(match: re.Match[str]) -> str:
            raw_target = match.group("target")
            target = raw_target[1:-1] if raw_target.startswith("<") else raw_target
            if is_external_target(target):
                return match.group(0)

            decoded = unquote(target)
            source = (markdown_path.parent / decoded).resolve()
            try:
                source.relative_to(extract_root.resolve())
            except ValueError as exc:
                raise NotionImportError(f"图片路径越出导出目录：{target}") from exc
            if not source.is_file():
                raise NotionImportError(f"找不到本地图片：{source}")

            destination = destination_for(source)
            public_path = "/" + destination.relative_to(repo_root).as_posix()
            return match.group("prefix") + public_path + match.group("suffix")

        return IMAGE_RE.sub(replace, segment)

    output_lines = []
    for line in body.splitlines():
        fence = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if fence:
            marker = fence.group(1)
            if not fence_char:
                fence_char = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_length:
                fence_char = ""
                fence_length = 0
            output_lines.append(line)
            continue

        if fence_char:
            output_lines.append(line)
        else:
            output_lines.append(rewrite_markdown_line(line, rewrite_segment))

    ending = "\n" if body.endswith("\n") else ""
    return "\n".join(output_lines) + ending, list(assets.items())


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_post(
    metadata: dict[str, object], body: str, extra_front_matter: list[str] | None = None
) -> str:
    front_matter = [
        "---",
        f"title: {yaml_string(str(metadata['title']))}",
        f"date: {metadata['date']}",
        "categories: " + json.dumps(metadata["categories"], ensure_ascii=False),
        "tags: " + json.dumps(metadata["tags"], ensure_ascii=False),
    ]
    if metadata.get("permalink"):
        front_matter.append(f"permalink: {metadata['permalink']}")
    if metadata.get("description"):
        front_matter.append(f"description: {yaml_string(str(metadata['description']))}")
    if extra_front_matter:
        front_matter.extend(extra_front_matter)
    front_matter.extend(["---", "", ""])
    return "\n".join(front_matter) + body.lstrip("\n")


def import_archive(
    archive: Path,
    repo_root: Path,
    *,
    title: str | None = None,
    slug: str | None = None,
    post_id: int | str | None = None,
    date: str | None = None,
    categories: str | None = None,
    tags: str | None = None,
    description: str | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[Path, list[Path], str]:
    archive = archive.expanduser().resolve()
    repo_root = repo_root.expanduser().resolve()
    if not archive.is_file():
        raise NotionImportError(f"找不到导出文件：{archive}")
    if not (repo_root / "_posts").is_dir():
        raise NotionImportError(f"目标目录不是 Jekyll 仓库（缺少 _posts）：{repo_root}")

    with tempfile.TemporaryDirectory(prefix="notion-import-") as temp_dir:
        extract_root = Path(temp_dir)
        safe_extract(archive, extract_root)
        markdown_path = find_markdown(extract_root)
        metadata, body = parse_article(markdown_path)

        overrides = {
            "title": title,
            "slug": slug,
            "date": date,
            "description": description,
        }
        for key, value in overrides.items():
            if value is not None:
                metadata[key] = value.strip()
        if post_id is not None:
            metadata["post_id"] = str(post_id).strip()
        if categories is not None:
            metadata["categories"] = categories
        if tags is not None:
            metadata["tags"] = tags

        status = metadata.get("status", "")
        if status == "草稿":
            raise NotionImportError("文章状态仍为「草稿」；请先在 Notion 改为「待发布」。")

        final_title = str(metadata.get("title", "")).strip()
        raw_slug = str(metadata.get("slug", "")).strip()
        raw_post_id = str(metadata.get("post_id", "")).strip()
        final_date = str(metadata.get("date", "")).strip()
        if not final_title:
            raise NotionImportError("缺少文章标题；请使用 --title 指定。")
        if raw_slug and not SLUG_RE.fullmatch(raw_slug):
            raise NotionImportError(
                f"Slug 无效：{raw_slug!r}；仅允许小写英文、数字和连字符，例如 my-first-post。"
            )
        if not final_date:
            raise NotionImportError("缺少发布日期；请使用 --date YYYY-MM-DD 指定。")

        filename_date, chirpy_date = normalize_date(final_date)
        used_ids = scan_post_ids(repo_root)

        provisional_path = (
            repo_root / "_posts" / f"{filename_date}-{raw_slug}.md" if raw_slug else None
        )
        if raw_post_id:
            final_post_id = parse_post_id(raw_post_id, label="Post ID")
            owner = used_ids.get(final_post_id)
            target_slug = raw_slug or f"id-{final_post_id}"
            target_path = repo_root / "_posts" / f"{filename_date}-{target_slug}.md"
            if owner is not None and not (force and owner == target_path):
                raise NotionImportError(
                    f"Post ID {final_post_id} 已被 {owner.name} 占用，请换一个编号。"
                )
        elif provisional_path and provisional_path.exists() and force:
            existing_id = extract_post_id(provisional_path.read_text(encoding="utf-8"))
            final_post_id = existing_id if existing_id is not None else next_post_id(set(used_ids))
        else:
            final_post_id = next_post_id(set(used_ids))

        final_slug = raw_slug or f"id-{final_post_id}"
        post_path = repo_root / "_posts" / f"{filename_date}-{final_slug}.md"
        if post_path.exists() and not force:
            raise NotionImportError(f"文章已存在：{post_path}；如确认覆盖，请添加 --force。")

        rewritten_body, asset_pairs = rewrite_images(
            body, markdown_path, extract_root, final_slug, repo_root
        )
        final_metadata = {
            "title": final_title,
            "date": chirpy_date,
            "categories": split_options(categories if categories is not None else metadata.get("categories")),
            "tags": split_options(tags if tags is not None else metadata.get("tags")),
            "permalink": format_permalink(final_post_id),
            "description": str(metadata.get("description", "")).strip(),
        }
        rendered = render_post(final_metadata, rewritten_body)

        if not dry_run:
            post_path.parent.mkdir(parents=True, exist_ok=True)
            for source, destination in asset_pairs:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    shutil.copy2(source, destination)
            temporary_post = post_path.with_name(post_path.name + ".tmp")
            temporary_post.write_text(rendered, encoding="utf-8")
            os.replace(temporary_post, post_path)

        return post_path, [destination for _, destination in asset_pairs], rendered


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="将单篇 Notion Markdown & CSV 导出 ZIP 导入 Chirpy/Jekyll。"
    )
    parser.add_argument("archive", type=Path, help="Notion 导出的 ZIP 文件")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1], help=argparse.SUPPRESS)
    parser.add_argument("--title", help="文章标题（覆盖导出内容）")
    parser.add_argument("--slug", help="可选：小写英文短名称（留空则自动使用 id-<编号>）")
    parser.add_argument("--post-id", type=int, help="可选：指定文章数字 ID（留空则自动按最大编号 + 1 递增）")
    parser.add_argument("--date", help="发布日期，例如 2026-11-17")
    parser.add_argument("--categories", help="逗号分隔的分类，例如 安全研究,IoT")
    parser.add_argument("--tags", help="逗号分隔的标签，例如 Notion,Jekyll,博客")
    parser.add_argument("--description", help="可选的文章摘要")
    parser.add_argument("--force", action="store_true", help="覆盖同名的已导入文章，不清理旧图片")
    parser.add_argument("--dry-run", action="store_true", help="只检查和预览，不写入文件")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        post_path, assets, rendered = import_archive(
            args.archive,
            args.repo,
            title=args.title,
            slug=args.slug,
            post_id=args.post_id,
            date=args.date,
            categories=args.categories,
            tags=args.tags,
            description=args.description,
            force=args.force,
            dry_run=args.dry_run,
        )
    except (NotionImportError, OSError, UnicodeError) as exc:
        print(f"导入失败：{exc}", file=sys.stderr)
        return 1

    action = "将写入" if args.dry_run else "已写入"
    print(f"{action}文章：{post_path}")
    if assets:
        print(f"{action} {len(assets)} 个图片文件：")
        for asset in assets:
            print(f"  - {asset}")
    else:
        print("没有需要导入的本地图片。")
    if args.dry_run:
        print("\n--- 文章预览 ---\n")
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
