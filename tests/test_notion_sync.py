from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "notion_sync.py"
SPEC = importlib.util.spec_from_file_location("notion_sync", MODULE_PATH)
assert SPEC and SPEC.loader
notion_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = notion_sync
SPEC.loader.exec_module(notion_sync)


def text(value: str, **annotations):
    return {
        "type": "text",
        "plain_text": value,
        "href": None,
        "annotations": annotations,
    }


def block(block_id: str, block_type: str, **data):
    children = data.pop("_children", None)
    result = {"id": block_id, "type": block_type, block_type: data}
    if children is not None:
        result["_children"] = children
    return result


def page(page_id: str, title: str = "测试文章", slug: str = "sync-test", status: str = "待发布"):
    return {
        "id": page_id,
        "properties": {
            "Title": {"title": [text(title)]},
            "Slug": {"rich_text": [text(slug)]},
            "Status": {"status": {"name": status}},
            "Date": {"date": {"start": "2026-11-17T19:00:00.000+08:00"}},
            "Categories": {"multi_select": [{"name": "随笔"}]},
            "Tags": {"multi_select": [{"name": "Notion"}, {"name": "Jekyll"}]},
        },
    }


class FakeClient:
    def __init__(self, pages, trees):
        self.pages = pages
        self.trees = trees

    def query_articles(self):
        return self.pages

    def block_tree(self, page_id):
        return self.trees[page_id]


class FakePruneClient(FakeClient):
    def __init__(self, pages, trees, page_states):
        super().__init__(pages, trees)
        self.page_states = page_states
        self.page_requests = []

    def get_page(self, page_id):
        self.page_requests.append(page_id)
        return self.page_states[page_id]


class NotionSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp_context = tempfile.TemporaryDirectory(prefix="notion-sync-test-")
        self.temp = Path(self.temp_context.name).resolve()
        self.repo = self.temp / "repo"
        (self.repo / "_posts").mkdir(parents=True)
        self.page_id = "41b888f9-4af3-8141-bdd5-c0f42fd4aa4e"

    def tearDown(self):
        self.temp_context.cleanup()

    def test_syncs_common_blocks_and_downloads_notion_images(self):
        image_url = "https://files.notion.test/image%20one.png?signature=temporary"
        tree = [
            block("p1", "paragraph", rich_text=[text("Hello "), text("Notion", bold=True)]),
            block("h2", "heading_2", rich_text=[text("正文")]),
            block("li", "bulleted_list_item", rich_text=[text("项目")]),
            block("code", "code", rich_text=[text("print('ok')")], language="python"),
            block(
                "img",
                "image",
                type="file",
                file={"url": image_url},
                caption=[text("截图")],
            ),
            block(
                "table",
                "table",
                table_width=2,
                _children=[
                    block("row1", "table_row", cells=[[text("名称")], [text("值")]]),
                    block("row2", "table_row", cells=[[text("A")], [text("B")]]),
                ],
            ),
        ]
        client = FakeClient([page(self.page_id)], {self.page_id: tree})
        downloads = []

        def fake_download(url, destination):
            downloads.append(url)
            destination.write_bytes(b"image-data")

        plans = notion_sync.sync_articles(client, self.repo, downloader=fake_download)

        self.assertEqual(plans[0].state, "create")
        post = self.repo / "_posts" / "2026-11-17-sync-test.md"
        rendered = post.read_text(encoding="utf-8")
        self.assertIn('title: "测试文章"', rendered)
        self.assertIn("date: 2026-11-17 19:00:00 +0800", rendered)
        self.assertIn("permalink: /posts/id=1/", rendered)
        self.assertIn(f'notion_id: "{self.page_id}"', rendered)
        self.assertIn("Hello **Notion**", rendered)
        self.assertIn("## 正文", rendered)
        self.assertIn("- 项目\n\n```python\nprint('ok')\n```", rendered)
        self.assertIn("| 名称 | 值 |", rendered)
        self.assertEqual(downloads, [image_url])
        self.assertEqual(len(plans[0].assets), 1)
        self.assertEqual(plans[0].assets[0].destination.read_bytes(), b"image-data")
        self.assertIn("![截图](/assets/img/posts/sync-test/", rendered)

    def test_dry_run_does_not_write_or_download(self):
        tree = [block("p1", "paragraph", rich_text=[text("正文")])]
        client = FakeClient([page(self.page_id)], {self.page_id: tree})

        def unexpected_download(url, destination):
            raise AssertionError("dry-run should not download")

        plans = notion_sync.sync_articles(
            client, self.repo, dry_run=True, downloader=unexpected_download
        )

        self.assertEqual(plans[0].state, "create")
        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_managed_post_can_be_updated_without_force(self):
        page_data = page(self.page_id)
        old_tree = [block("p1", "paragraph", rich_text=[text("旧正文")])]
        client = FakeClient([page_data], {self.page_id: old_tree})
        notion_sync.sync_articles(client, self.repo)

        client.trees[self.page_id] = [block("p1", "paragraph", rich_text=[text("新正文")])]
        plans = notion_sync.sync_articles(client, self.repo)

        post = self.repo / "_posts" / "2026-11-17-sync-test.md"
        self.assertEqual(plans[0].state, "update")
        self.assertIn("新正文", post.read_text(encoding="utf-8"))

    def test_unowned_post_requires_force(self):
        post = self.repo / "_posts" / "2026-11-17-sync-test.md"
        post.write_text("local content", encoding="utf-8")
        tree = [block("p1", "paragraph", rich_text=[text("Notion 正文")])]
        client = FakeClient([page(self.page_id)], {self.page_id: tree})

        with self.assertRaises(notion_sync.NotionImportError):
            notion_sync.sync_articles(client, self.repo)
        self.assertEqual(post.read_text(encoding="utf-8"), "local content")

        notion_sync.sync_articles(client, self.repo, force=True)
        self.assertIn("Notion 正文", post.read_text(encoding="utf-8"))

    def test_duplicate_output_paths_fail_before_writing(self):
        other_id = "41b888f9-4af3-81a2-aac4-d40d6d16dc29"
        pages = [page(self.page_id), page(other_id, title="重复文章")]
        trees = {
            self.page_id: [block("p1", "paragraph", rich_text=[text("一")])],
            other_id: [block("p2", "paragraph", rich_text=[text("二")])],
        }

        with self.assertRaises(notion_sync.NotionImportError):
            notion_sync.sync_articles(FakeClient(pages, trees), self.repo)

        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_unsupported_block_fails_without_partial_output(self):
        tree = [block("unknown", "video", type="external", external={"url": "https://example.com"})]
        client = FakeClient([page(self.page_id)], {self.page_id: tree})

        with self.assertRaises(notion_sync.NotionImportError):
            notion_sync.sync_articles(client, self.repo)

        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_sync_never_deletes_unrelated_local_posts(self):
        keep = self.repo / "_posts" / "2020-01-01-keep.md"
        keep.write_text("keep", encoding="utf-8")
        client = FakeClient([], {})

        plans = notion_sync.sync_articles(client, self.repo)

        self.assertEqual(plans, [])
        self.assertEqual(keep.read_text(encoding="utf-8"), "keep")

    def test_new_draft_is_skipped_without_fetching_blocks(self):
        draft_page = page(self.page_id, status="草稿")
        client = FakeClient([draft_page], {})

        plans = notion_sync.sync_articles(client, self.repo)

        self.assertEqual(plans, [])
        self.assertEqual(list((self.repo / "_posts").iterdir()), [])

    def test_database_query_reads_all_article_statuses(self):
        client = notion_sync.NotionClient("token-not-recorded", self.page_id)
        calls = []

        def fake_request(endpoint, payload=None):
            calls.append((endpoint, payload))
            return {"results": [], "has_more": False, "next_cursor": None}

        client._request = fake_request
        self.assertEqual(client.query_articles(), [])
        payload = calls[0][1]
        self.assertNotIn("filter", payload)

    def test_default_sync_deletes_only_confirmed_archived_and_draft_posts(self):
        archived_id = self.page_id
        missing_id = "41b888f9-4af3-81a2-aac4-d40d6d16dc29"
        draft_id = "41b888f9-4af3-810a-8dde-cb907aeb2aa2"
        archived = self.repo / "_posts" / "2026-01-01-archived.md"
        missing = self.repo / "_posts" / "2026-01-02-missing.md"
        draft = self.repo / "_posts" / "2026-01-03-draft.md"
        local = self.repo / "_posts" / "2026-01-04-local.md"
        for path, page_id in ((archived, archived_id), (missing, missing_id), (draft, draft_id)):
            path.write_text(f'---\nnotion_id: "{page_id}"\n---\n', encoding="utf-8")
        local.write_text("local", encoding="utf-8")
        client = FakePruneClient(
            [],
            {},
            {
                archived_id: {"archived": True},
                missing_id: None,
                draft_id: {
                    "archived": False,
                    "properties": {"Status": {"status": {"name": "草稿"}}},
                },
            },
        )

        notion_sync.sync_articles(client, self.repo, prune=False)
        self.assertEqual(client.page_requests, [])
        self.assertTrue(archived.exists())

        plans = notion_sync.sync_articles(client, self.repo, dry_run=True)
        self.assertEqual([plan.state for plan in plans], ["delete", "delete"])
        self.assertEqual([plan.path for plan in plans], [archived, draft])
        self.assertTrue(archived.exists())
        self.assertTrue(draft.exists())

        notion_sync.sync_articles(client, self.repo)
        self.assertFalse(archived.exists())
        self.assertTrue(missing.exists())
        self.assertFalse(draft.exists())
        self.assertTrue(local.exists())

    def test_get_page_returns_none_only_for_404(self):
        client = notion_sync.NotionClient("token-not-recorded", self.page_id)

        def fake_request(endpoint, payload=None):
            raise notion_sync.NotionAPIError(404, "not found")

        client._request = fake_request
        self.assertIsNone(client.get_page(self.page_id))

    def test_env_file_parsing(self):
        env = self.temp / ".env.notion"
        env.write_text(
            "# comment\nNOTION_TOKEN='secret-value'\nexport NOTION_DATABASE_ID=\"database-id\"\n",
            encoding="utf-8",
        )
        values = notion_sync.load_env_file(env)
        self.assertEqual(values["NOTION_TOKEN"], "secret-value")
        self.assertEqual(values["NOTION_DATABASE_ID"], "database-id")

    def test_auto_increments_post_id_after_hidden_posts_without_slug(self):
        old_post = self.repo / "_posts" / "2025-04-18-旧文章.md"
        old_post.write_text(
            "---\ntitle: 旧文章\npermalink: /posts/id=107/\npublished: false\n---\n\n旧内容\n",
            encoding="utf-8",
        )
        first_id = self.page_id
        second_id = "41b888f9-4af3-81a2-aac4-d40d6d16dc29"
        page_later = {
            "id": second_id,
            "properties": {
                "Title": {"title": [text("第二篇中文文章")]},
                "Status": {"status": {"name": "待发布"}},
                "Date": {"date": {"start": "2026-11-22"}},
                "Categories": {"multi_select": []},
                "Tags": {"multi_select": []},
            },
        }
        page_earlier = {
            "id": first_id,
            "properties": {
                "Title": {"title": [text("第一篇中文文章")]},
                "Slug": {"rich_text": []},
                "Status": {"status": {"name": "待发布"}},
                "Date": {"date": {"start": "2026-11-21"}},
                "Categories": {"multi_select": [{"name": "随笔"}]},
                "Tags": {"multi_select": []},
            },
        }
        trees = {
            first_id: [
                block(
                    "img1",
                    "image",
                    type="file",
                    file={"url": "https://files.notion.test/a.png?sig=1"},
                    caption=[text("图一")],
                )
            ],
            second_id: [block("p2", "paragraph", rich_text=[text("内容二")])],
        }
        client = FakeClient([page_later, page_earlier], trees)

        def fake_download(url, destination):
            destination.write_bytes(b"png")

        plans = notion_sync.sync_articles(client, self.repo, downloader=fake_download)

        post_108 = self.repo / "_posts" / "2026-11-21-id-108.md"
        post_109 = self.repo / "_posts" / "2026-11-22-id-109.md"
        self.assertTrue(post_108.exists())
        self.assertTrue(post_109.exists())
        text_108 = post_108.read_text(encoding="utf-8")
        text_109 = post_109.read_text(encoding="utf-8")
        self.assertIn("permalink: /posts/id=108/", text_108)
        self.assertIn("![图一](/assets/img/posts/id-108/", text_108)
        self.assertIn("permalink: /posts/id=109/", text_109)
        self.assertEqual(sorted(p.permalink for p in plans), ["/posts/id=108/", "/posts/id=109/"])

        # Re-syncing after changing the date preserves id=108 and cleans up old file
        page_earlier["properties"]["Date"] = {"date": {"start": "2026-11-23"}}
        plans_after = notion_sync.sync_articles(client, self.repo, downloader=fake_download)
        moved_108 = self.repo / "_posts" / "2026-11-23-id-108.md"
        self.assertFalse(post_108.exists())
        self.assertTrue(moved_108.exists())
        self.assertIn("permalink: /posts/id=108/", moved_108.read_text(encoding="utf-8"))
        self.assertEqual(
            {p.page_id: p.state for p in plans_after}[first_id],
            "update",
        )

    def test_explicit_post_id_collision_fails(self):
        old_post = self.repo / "_posts" / "2025-04-18-旧文章.md"
        old_post.write_text(
            "---\ntitle: 旧文章\npermalink: /posts/id=107/\npublished: false\n---\n\n旧内容\n",
            encoding="utf-8",
        )
        p = page(self.page_id, slug="")
        p["properties"]["Post ID"] = {"type": "number", "number": 107}
        client = FakeClient([p], {self.page_id: [block("p1", "paragraph", rich_text=[text("冲突")])]})

        with self.assertRaises(notion_sync.NotionImportError):
            notion_sync.sync_articles(client, self.repo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
