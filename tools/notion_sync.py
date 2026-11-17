#!/usr/bin/env python3
"""Synchronize ready/published articles directly from a Notion database.

Requires a Notion internal integration token with read access to the database.
Credentials are read from NOTION_TOKEN or the git-ignored .env.notion file.
Only Python's standard library is used; downloaded files are never executed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen
import uuid

MODULE_PATH = Path(__file__).resolve().with_name("notion_import.py")
SPEC = importlib.util.spec_from_file_location("notion_import", MODULE_PATH)
if not SPEC or not SPEC.loader:
    raise RuntimeError(f"无法加载 {MODULE_PATH}")
notion_import = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = notion_import
SPEC.loader.exec_module(notion_import)
NotionImportError = notion_import.NotionImportError

API_ROOT = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"
MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_DOWNLOAD_BYTES = 200 * 1024 * 1024
MAX_BLOCK_DEPTH = 20
READY_STATUSES = ("待发布", "已发布")


def plain_text(items: list[dict] | None) -> str:
    return "".join(item.get("plain_text", "") for item in items or [])


def escape_markdown(text: str) -> str:
    for character in ("\\", "`", "*", "_", "[", "]"):
        text = text.replace(character, "\\" + character)
    return text


def rich_text(items: list[dict] | None) -> str:
    output = []
    for item in items or []:
        if item.get("type") == "equation":
            expression = item.get("equation", {}).get("expression", "")
            output.append(f"${expression}$")
            continue

        text = escape_markdown(item.get("plain_text", ""))
        annotations = item.get("annotations", {})
        if annotations.get("code"):
            fence = "``" if "`" in text else "`"
            text = f"{fence}{item.get('plain_text', '')}{fence}"
        else:
            if annotations.get("bold"):
                text = f"**{text}**"
            if annotations.get("italic"):
                text = f"*{text}*"
            if annotations.get("strikethrough"):
                text = f"~~{text}~~"

        href = item.get("href")
        if href:
            safe_href = href.replace(" ", "%20").replace(")", "%29")
            text = f"[{text}]({safe_href})"
        output.append(text)
    return "".join(output)


def normalize_database_id(value: str) -> str:
    match = re.search(r"(?i)([0-9a-f]{32}|[0-9a-f-]{36})", value.strip())
    if not match:
        raise NotionImportError("NOTION_DATABASE_ID 无效；请填写数据库 ID 或完整链接。")
    try:
        return str(uuid.UUID(match.group(1)))
    except ValueError as exc:
        raise NotionImportError("NOTION_DATABASE_ID 不是有效 UUID。") from exc


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise NotionImportError(f"{path}:{number} 不是 KEY=VALUE 格式。")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            raise NotionImportError(f"{path}:{number} 包含无效变量名。")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


class NotionClient:
    def __init__(self, token: str, database_id: str, timeout: int = 30):
        self.token = token
        self.database_id = normalize_database_id(database_id)
        self.timeout = timeout

    def _request(self, endpoint: str, payload: dict | None = None) -> dict:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(
            API_ROOT + endpoint,
            data=body,
            method="GET" if body is None else "POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Notion-Version": NOTION_VERSION,
                "Content-Type": "application/json",
                "User-Agent": "ef4tless-notion-sync/1.0",
            },
        )
        for attempt in range(3):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    return json.load(response)
            except HTTPError as exc:
                detail = exc.read(4096).decode("utf-8", errors="replace")
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if retryable and attempt < 2:
                    retry_after = exc.headers.get("Retry-After")
                    time.sleep(float(retry_after) if retry_after else 2**attempt)
                    continue
                raise NotionImportError(
                    f"Notion API 返回 HTTP {exc.code}：{detail}"
                ) from exc
            except URLError as exc:
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
                raise NotionImportError(f"无法连接 Notion API：{exc.reason}") from exc
        raise AssertionError("unreachable")

    def query_articles(self) -> list[dict]:
        pages = []
        cursor = None
        while True:
            payload = {
                "page_size": 100,
                "filter": {
                    "or": [
                        {"property": "Status", "status": {"equals": status}}
                        for status in READY_STATUSES
                    ]
                },
            }
            if cursor:
                payload["start_cursor"] = cursor
            result = self._request(f"/databases/{self.database_id}/query", payload)
            pages.extend(result.get("results", []))
            if not result.get("has_more"):
                return pages
            cursor = result.get("next_cursor")
            if not cursor:
                raise NotionImportError("Notion 分页响应缺少 next_cursor。")

    def block_children(self, block_id: str) -> list[dict]:
        blocks = []
        cursor = None
        while True:
            endpoint = f"/blocks/{block_id}/children?page_size=100"
            if cursor:
                endpoint += f"&start_cursor={cursor}"
            result = self._request(endpoint)
            blocks.extend(result.get("results", []))
            if not result.get("has_more"):
                return blocks
            cursor = result.get("next_cursor")
            if not cursor:
                raise NotionImportError("Notion 块分页响应缺少 next_cursor。")

    def block_tree(self, page_id: str, depth: int = 0) -> list[dict]:
        if depth > MAX_BLOCK_DEPTH:
            raise NotionImportError(f"Notion 块嵌套超过 {MAX_BLOCK_DEPTH} 层。")
        blocks = self.block_children(page_id)
        for block in blocks:
            if block.get("has_children"):
                block["_children"] = self.block_tree(block["id"], depth + 1)
        return blocks


@dataclass(frozen=True)
class Asset:
    url: str
    destination: Path


class NotionRenderer:
    def __init__(self, repo_root: Path, slug: str):
        self.repo_root = repo_root
        self.slug = slug
        self.assets: list[Asset] = []
        self._asset_by_url: dict[str, Asset] = {}

    def image_url(self, block: dict) -> str:
        data = block[block["type"]]
        source_type = data.get("type")
        source = data.get(source_type, {})
        url = source.get("url", "")
        if source_type == "external":
            return url
        if source_type != "file" or not url:
            raise NotionImportError(f"图片块 {block['id']} 缺少文件 URL。")
        if url in self._asset_by_url:
            return self.public_path(self._asset_by_url[url].destination)

        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise NotionImportError("Notion 图片下载地址必须是有效 HTTPS URL。")
        raw_name = Path(unquote(parsed.path)).name or "image.png"
        clean_name = re.sub(r"[^\w.\-]+", "-", raw_name, flags=re.UNICODE).strip(".-")
        clean_name = clean_name or "image.png"
        if not Path(clean_name).suffix:
            clean_name += ".png"
        digest = hashlib.sha256(parsed.path.encode("utf-8")).hexdigest()[:12]
        destination = self.repo_root / "assets/img/posts" / self.slug / f"{digest}-{clean_name}"
        asset = Asset(url=url, destination=destination)
        self.assets.append(asset)
        self._asset_by_url[url] = asset
        return self.public_path(destination)

    def public_path(self, destination: Path) -> str:
        return "/" + destination.relative_to(self.repo_root).as_posix()

    def render(self, blocks: list[dict], depth: int = 0) -> str:
        lines = self.render_lines(blocks, depth)
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines).rstrip() + "\n"

    def render_lines(self, blocks: list[dict], depth: int = 0) -> list[str]:
        lines: list[str] = []
        indent = "  " * depth
        for block in blocks:
            block_type = block.get("type")
            data = block.get(block_type, {})
            children = block.get("_children", [])

            if block_type == "paragraph":
                lines.extend([indent + rich_text(data.get("rich_text")), ""])
            elif block_type in ("heading_1", "heading_2", "heading_3"):
                level = int(block_type[-1])
                lines.extend([indent + "#" * level + " " + rich_text(data.get("rich_text")), ""])
            elif block_type in ("bulleted_list_item", "numbered_list_item", "to_do"):
                if block_type == "bulleted_list_item":
                    marker = "-"
                elif block_type == "numbered_list_item":
                    marker = "1."
                else:
                    marker = "- [x]" if data.get("checked") else "- [ ]"
                lines.append(f"{indent}{marker} {rich_text(data.get('rich_text'))}")
                if children:
                    lines.extend(self.render_lines(children, depth + 1))
            elif block_type in ("quote", "callout", "toggle"):
                text = rich_text(data.get("rich_text"))
                if block_type == "callout":
                    icon = data.get("icon", {}).get("emoji", "")
                    text = f"{icon} {text}".strip()
                if block_type == "toggle":
                    text = f"**{text}**"
                lines.append(indent + "> " + text)
                for child_line in self.render_lines(children, depth):
                    lines.append(indent + "> " + child_line if child_line else ">")
                if block_type == "callout":
                    lines.append("{: .prompt-info }")
                lines.append("")
            elif block_type == "code":
                content = plain_text(data.get("rich_text"))
                longest = max((len(run) for run in re.findall(r"`+", content)), default=0)
                fence = "`" * max(3, longest + 1)
                language = data.get("language", "")
                if language == "plain text":
                    language = "text"
                lines.extend([indent + fence + language, *content.splitlines(), indent + fence, ""])
            elif block_type == "divider":
                lines.extend([indent + "---", ""])
            elif block_type == "image":
                caption = plain_text(data.get("caption")) or "image"
                caption = caption.replace("[", "\\[").replace("]", "\\]")
                lines.extend([f"{indent}![{caption}]({self.image_url(block)})", ""])
            elif block_type in ("bookmark", "link_preview", "embed"):
                url = data.get("url", "")
                lines.extend([f"{indent}<{url}>", ""])
            elif block_type == "equation":
                lines.extend([indent + "$$", data.get("expression", ""), indent + "$$", ""])
            elif block_type == "table":
                lines.extend(self.render_table(children, indent))
            elif block_type == "child_page":
                page_url = "https://www.notion.so/" + block["id"].replace("-", "")
                lines.extend([f"{indent}[{escape_markdown(data.get('title', '子页面'))}]({page_url})", ""])
            elif block_type in ("column_list", "column", "synced_block"):
                lines.extend(self.render_lines(children, depth))
                lines.append("")
            else:
                raise NotionImportError(
                    f"暂不支持 Notion 块类型 {block_type!r}（块 ID：{block.get('id')}）。"
                    "为避免丢失内容，已停止同步。"
                )

            if children and block_type not in (
                "bulleted_list_item",
                "numbered_list_item",
                "to_do",
                "quote",
                "callout",
                "toggle",
                "table",
                "column_list",
                "column",
                "synced_block",
            ):
                lines.extend(self.render_lines(children, depth))
        return lines

    def render_table(self, rows: list[dict], indent: str) -> list[str]:
        if not rows:
            return []
        rendered_rows = []
        for row in rows:
            if row.get("type") != "table_row":
                raise NotionImportError("表格中包含非 table_row 子块。")
            cells = row.get("table_row", {}).get("cells", [])
            values = [rich_text(cell).replace("|", "\\|").replace("\n", "<br>") for cell in cells]
            rendered_rows.append(indent + "| " + " | ".join(values) + " |")
        width = len(rows[0].get("table_row", {}).get("cells", []))
        separator = indent + "| " + " | ".join(["---"] * width) + " |"
        return [rendered_rows[0], separator, *rendered_rows[1:], ""]


@dataclass
class SyncPlan:
    page_id: str
    title: str
    path: Path
    content: str
    assets: list[Asset]
    state: str = "unchanged"


def page_metadata(page: dict) -> dict[str, object]:
    properties = page.get("properties", {})

    def prop(name: str) -> dict:
        value = properties.get(name)
        if value is None:
            raise NotionImportError(f"Notion 数据库缺少属性 {name!r}。")
        return value

    title = plain_text(prop("Title").get("title")).strip()
    slug = plain_text(prop("Slug").get("rich_text")).strip()
    status = (prop("Status").get("status") or {}).get("name", "")
    date = (prop("Date").get("date") or {}).get("start", "")
    categories = [item["name"] for item in prop("Categories").get("multi_select", [])]
    tags = [item["name"] for item in prop("Tags").get("multi_select", [])]
    description_property = properties.get("Description", {})
    description = plain_text(description_property.get("rich_text")).strip()

    if not title:
        raise NotionImportError(f"页面 {page.get('id')} 缺少 Title。")
    if not notion_import.SLUG_RE.fullmatch(slug):
        raise NotionImportError(f"文章 {title!r} 的 Slug 无效：{slug!r}")
    if status not in READY_STATUSES:
        raise NotionImportError(f"文章 {title!r} 的状态不在同步范围内：{status!r}")
    filename_date, chirpy_date = notion_import.normalize_date(date)
    return {
        "title": title,
        "slug": slug,
        "date": chirpy_date,
        "filename_date": filename_date,
        "categories": categories,
        "tags": tags,
        "description": description,
    }


def existing_notion_id(path: Path) -> str | None:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    match = re.search(r"(?m)^notion_id:\s*[\"']?([0-9a-fA-F-]{36})[\"']?\s*$", text)
    return match.group(1).lower() if match else None


def prepare_sync(client: NotionClient, repo_root: Path) -> list[SyncPlan]:
    pages = client.query_articles()
    plans = []
    seen_paths: dict[Path, str] = {}
    for page in pages:
        metadata = page_metadata(page)
        slug = str(metadata["slug"])
        post_path = repo_root / "_posts" / f"{metadata['filename_date']}-{slug}.md"
        if post_path in seen_paths:
            raise NotionImportError(
                f"多篇文章指向同一路径 {post_path}；请检查重复 Slug 或日期。"
            )
        seen_paths[post_path] = page["id"]

        renderer = NotionRenderer(repo_root, slug)
        body = renderer.render(client.block_tree(page["id"]))
        content = notion_import.render_post(
            metadata,
            body,
            extra_front_matter=[f"notion_id: {notion_import.yaml_string(page['id'])}"],
        )
        plans.append(
            SyncPlan(
                page_id=page["id"],
                title=str(metadata["title"]),
                path=post_path,
                content=content,
                assets=renderer.assets,
            )
        )
    return plans


def download_image(url: str, destination: Path) -> None:
    request = Request(url, headers={"User-Agent": "ef4tless-notion-sync/1.0"})
    try:
        with urlopen(request, timeout=45) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_IMAGE_BYTES:
                raise NotionImportError(f"图片超过 20 MiB：{url}")
            with destination.open("wb") as output:
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_IMAGE_BYTES:
                        raise NotionImportError(f"图片超过 20 MiB：{url}")
                    output.write(chunk)
    except (HTTPError, URLError, OSError) as exc:
        raise NotionImportError(f"下载 Notion 图片失败：{url}（{exc}）") from exc


def sync_articles(
    client: NotionClient,
    repo_root: Path,
    *,
    dry_run: bool = False,
    force: bool = False,
    downloader: Callable[[str, Path], None] = download_image,
) -> list[SyncPlan]:
    repo_root = repo_root.resolve()
    if not (repo_root / "_posts").is_dir():
        raise NotionImportError(f"目标目录不是 Jekyll 仓库：{repo_root}")
    plans = prepare_sync(client, repo_root)

    for plan in plans:
        if not plan.path.exists():
            plan.state = "create"
            continue
        current = plan.path.read_text(encoding="utf-8")
        owner = existing_notion_id(plan.path)
        if owner and owner != plan.page_id.lower():
            raise NotionImportError(f"{plan.path} 已属于另一篇 Notion 文章，停止覆盖。")
        if current == plan.content:
            plan.state = "unchanged"
        elif owner is None and not force:
            raise NotionImportError(
                f"{plan.path} 不是由本工具管理；首次接管请确认差异后使用 --force。"
            )
        else:
            plan.state = "update"

    if dry_run:
        return plans

    unique_assets = {asset.destination: asset for plan in plans for asset in plan.assets}
    missing_assets = [asset for asset in unique_assets.values() if not asset.destination.exists()]
    if sum(asset.destination.stat().st_size for asset in unique_assets.values() if asset.destination.exists()) > MAX_TOTAL_DOWNLOAD_BYTES:
        raise NotionImportError("同步图片总量超过 200 MiB 安全上限。")

    with tempfile.TemporaryDirectory(prefix="notion-sync-") as temp_dir:
        staged: dict[Path, Path] = {}
        downloaded_total = 0
        for index, asset in enumerate(missing_assets):
            stage = Path(temp_dir) / str(index)
            downloader(asset.url, stage)
            downloaded_total += stage.stat().st_size
            if downloaded_total > MAX_TOTAL_DOWNLOAD_BYTES:
                raise NotionImportError("本次下载图片总量超过 200 MiB 安全上限。")
            staged[asset.destination] = stage

        for destination, stage in staged.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stage, destination)

        for plan in plans:
            if plan.state == "unchanged":
                continue
            plan.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = plan.path.with_name(plan.path.name + ".tmp")
            temporary.write_text(plan.content, encoding="utf-8")
            os.replace(temporary, plan.path)

    return plans


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="直接同步 Notion 数据库中的「待发布 + 已发布」文章，跳过草稿。"
    )
    parser.add_argument("--database-id", help="Notion 数据库 ID 或链接；也可写入 .env.notion")
    parser.add_argument("--env-file", type=Path, help="凭据文件，默认 <仓库>/.env.notion")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1], help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help="只获取和检查，不写文件、不下载图片")
    parser.add_argument("--force", action="store_true", help="首次接管同路径但没有 notion_id 的本地文章")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo_root = args.repo.resolve()
    env_path = args.env_file or repo_root / ".env.notion"
    try:
        values = load_env_file(env_path)
        token = os.environ.get("NOTION_TOKEN") or values.get("NOTION_TOKEN", "")
        database_id = (
            args.database_id
            or os.environ.get("NOTION_DATABASE_ID")
            or values.get("NOTION_DATABASE_ID", "")
        )
        if not token:
            raise NotionImportError(
                f"缺少 NOTION_TOKEN；请在 {env_path} 中配置，不要提交该文件。"
            )
        if not database_id:
            raise NotionImportError("缺少 NOTION_DATABASE_ID；请填写数据库 ID 或链接。")
        client = NotionClient(token, database_id)
        plans = sync_articles(client, repo_root, dry_run=args.dry_run, force=args.force)
    except (NotionImportError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"同步失败：{exc}", file=sys.stderr)
        return 1

    if not plans:
        print("没有找到「待发布」或「已发布」文章；草稿不会同步。")
        return 0
    labels = {"create": "新增", "update": "更新", "unchanged": "无变化"}
    for plan in plans:
        print(f"[{labels[plan.state]}] {plan.title} → {plan.path}（图片 {len(plan.assets)}）")
    print(f"共 {len(plans)} 篇；{'仅检查，未写入' if args.dry_run else '同步完成'}。不会自动删除本地文章。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
