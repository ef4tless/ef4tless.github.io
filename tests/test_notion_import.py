from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "notion_import.py"
SPEC = importlib.util.spec_from_file_location("notion_import", MODULE_PATH)
assert SPEC and SPEC.loader
notion_import = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notion_import)


class NotionImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_context = tempfile.TemporaryDirectory(prefix="notion-import-test-")
        self.temp = Path(self.temp_context.name).resolve()
        self.repo = self.temp / "repo"
        (self.repo / "_posts").mkdir(parents=True)
        self.archive = self.temp / "export.zip"

    def tearDown(self) -> None:
        self.temp_context.cleanup()

    def make_archive(self, entries: dict[str, str | bytes]) -> Path:
        with zipfile.ZipFile(self.archive, "w") as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        return self.archive

    def test_imports_properties_and_rewrites_images_outside_code(self) -> None:
        directory = "Post 0123456789abcdef0123456789abcdef"
        self.make_archive(
            {
                f"{directory}.md": """# 测试文章

Slug: my-test-post
Status: 待发布
Date: 2026-11-17
Categories: 随笔, 测试
Tags: Notion，Jekyll
Description: 一篇摘要

正文 **加粗**。

![截图](Post%200123456789abcdef0123456789abcdef/screen%20shot.png "图片标题")

`![inline](inline.png)`

```text
![code](code.png)
```
""",
                f"{directory}/screen shot.png": b"fake-png-content",
            }
        )

        post, assets, _ = notion_import.import_archive(self.archive, self.repo)

        self.assertEqual(post, self.repo / "_posts" / "2026-11-17-my-test-post.md")
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].read_bytes(), b"fake-png-content")
        rendered = post.read_text(encoding="utf-8")
        self.assertIn('title: "测试文章"', rendered)
        self.assertIn("date: 2026-11-17 00:00:00 +0800", rendered)
        self.assertIn('categories: ["随笔", "测试"]', rendered)
        self.assertIn('tags: ["Notion", "Jekyll"]', rendered)
        self.assertIn('description: "一篇摘要"', rendered)
        self.assertIn(
            '![截图](/assets/img/posts/my-test-post/screen-shot.png "图片标题")',
            rendered,
        )
        self.assertIn("`![inline](inline.png)`", rendered)
        self.assertIn("![code](code.png)", rendered)
        self.assertNotIn("Slug: my-test-post", rendered)
        self.assertNotIn("# 测试文章", rendered)

    def test_cli_overrides_metadata(self) -> None:
        self.make_archive({"Original 0123456789abcdef0123456789abcdef.md": "# Original\n\nBody.\n"})

        post, _, rendered = notion_import.import_archive(
            self.archive,
            self.repo,
            title="覆盖标题",
            slug="cli-post",
            date="2026-11-18 20:30:00 +0800",
            categories="安全研究,IoT",
            tags="固件,测试",
            description="CLI 摘要",
        )

        self.assertEqual(post.name, "2026-11-18-cli-post.md")
        self.assertIn('title: "覆盖标题"', rendered)
        self.assertIn("date: 2026-11-18 20:30:00 +0800", rendered)
        self.assertIn('categories: ["安全研究", "IoT"]', rendered)
        self.assertIn('tags: ["固件", "测试"]', rendered)
        self.assertTrue(rendered.endswith("Body.\n"))

    def test_refuses_to_overwrite_without_force(self) -> None:
        self.make_archive({"Post.md": "# Title\n\nBody.\n"})
        existing = self.repo / "_posts" / "2026-11-17-my-post.md"
        existing.write_text("keep me", encoding="utf-8")

        with self.assertRaises(notion_import.NotionImportError):
            notion_import.import_archive(
                self.archive, self.repo, slug="my-post", date="2026-11-17"
            )

        self.assertEqual(existing.read_text(encoding="utf-8"), "keep me")

    def test_force_overwrites_post(self) -> None:
        self.make_archive({"Post.md": "# Title\n\nNew body.\n"})
        existing = self.repo / "_posts" / "2026-11-17-my-post.md"
        existing.write_text("old body", encoding="utf-8")

        notion_import.import_archive(
            self.archive,
            self.repo,
            slug="my-post",
            date="2026-11-17",
            force=True,
        )

        self.assertIn("New body.", existing.read_text(encoding="utf-8"))

    def test_missing_image_fails_before_writing_post(self) -> None:
        self.make_archive({"Post.md": "# Title\n\n![missing](missing.png)\n"})

        with self.assertRaises(notion_import.NotionImportError):
            notion_import.import_archive(
                self.archive, self.repo, slug="my-post", date="2026-11-17"
            )

        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_rejects_zip_path_traversal(self) -> None:
        self.make_archive({"../evil.md": "# Evil\n"})

        with self.assertRaises(notion_import.NotionImportError):
            notion_import.import_archive(
                self.archive, self.repo, slug="my-post", date="2026-11-17"
            )

        self.assertFalse((self.temp / "evil.md").exists())

    def test_rejects_multiple_markdown_files(self) -> None:
        self.make_archive({"One.md": "# One\n", "Two.md": "# Two\n"})

        with self.assertRaises(notion_import.NotionImportError):
            notion_import.import_archive(
                self.archive, self.repo, slug="my-post", date="2026-11-17"
            )

    def test_rejects_draft_status(self) -> None:
        self.make_archive(
            {"Post.md": "# Title\n\nSlug: my-post\nStatus: 草稿\nDate: 2026-11-17\n\nBody.\n"}
        )

        with self.assertRaises(notion_import.NotionImportError):
            notion_import.import_archive(self.archive, self.repo)

        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_dry_run_writes_nothing(self) -> None:
        self.make_archive({"Post.md": "# Title\n\nBody.\n"})

        post, _, rendered = notion_import.import_archive(
            self.archive,
            self.repo,
            slug="my-post",
            date="2026-11-17",
            dry_run=True,
        )

        self.assertIn("Body.", rendered)
        self.assertFalse(post.exists())
        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_external_images_are_left_unchanged(self) -> None:
        url = "https://example.com/image.png"
        self.make_archive({"Post.md": f"# Title\n\n![remote]({url})\n"})

        post, assets, rendered = notion_import.import_archive(
            self.archive, self.repo, slug="my-post", date="2026-11-17"
        )

        self.assertEqual(assets, [])
        self.assertIn(f"![remote]({url})", rendered)
        self.assertTrue(post.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
