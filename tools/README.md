# Notion → Jekyll 发布工具

推荐使用 `notion_sync.py` 直接同步 Notion 数据库，不需要逐篇导出。`notion_import.py` 保留为离线 ZIP 备用方案。

## 一、直接同步整个数据库（推荐）

### 同步规则

- 每次运行都查询整个 Blog 数据库，而不是只查询待发布文章。
- **待发布 / 已发布** → 新增或更新对应文章。
- **草稿** → 新草稿跳过；已经由工具管理的本地文章会撤下。
- **归档 / 回收站** → 删除对应的受管本地文章。
- Notion 是这些文章的正文来源；本地生成的 Markdown 中带有 `notion_id`，用于识别文章归属。
- 其他没有 `notion_id` 的旧文章不受影响，图片不自动删除。
- 不支持的内容块会停止整次同步，避免静默丢失正文。

### 1. 一次性配置 Notion Integration

1. 打开 [Notion Integrations](https://www.notion.so/profile/integrations)，创建一个 Internal Integration，并授予读取内容的权限。
2. 打开 Blog 数据库，在「··· → Connections / 连接」中添加这个 Integration。
3. 如果本地还没有凭据文件，复制示例：

```bash
cp -n tools/notion_sync.env.example .env.notion
chmod 600 .env.notion
```

4. 编辑 `.env.notion`：

```text
NOTION_TOKEN=你的-internal-integration-token
NOTION_DATABASE_ID=你的-Blog-数据库-ID
```

当前工作区已经生成了带 Blog 数据库 ID 的 `.env.notion`，只需填写 Token。该文件已被 `.gitignore` 忽略。**不要把真实 Token 提交到仓库或粘贴到聊天中。**

如果 macOS 上的 Python 报 `CERTIFICATE_VERIFY_FAILED`，可运行 `python3 -m pip install certifi` 安装根证书；脚本会自动使用 certifi，不会关闭证书验证。

### 2. 检查同步计划

```bash
python3 -I tools/notion_sync.py --dry-run
```

该命令会读取整个数据库并预览新增、更新和删除，但不写文件、不下载图片。

### 3. 正式同步

```bash
python3 -I tools/notion_sync.py
```

然后检查变更：

```bash
git status --short
git diff
git diff --check
bundle exec jekyll serve
```

打开 `http://127.0.0.1:4000` 检查文章，确认后提交并推送：

```bash
git add .
git commit -m "Sync blog posts from Notion"
git push origin main
```

等 GitHub Actions 部署成功并检查线上页面，再将刚发布的 Notion 文章状态改为 **已发布**。

### 删除文章或改为草稿

普通同步命令就会完整对账，**不需要额外的 `--prune` 参数**：

```bash
python3 -I tools/notion_sync.py --dry-run
python3 -I tools/notion_sync.py
```

安全规则：

- 只处理带有 `notion_id` 的本地文章；
- Notion API 明确返回 `archived`、`in_trash` 或当前状态为「草稿」时，才会撤下对应文章；
- 查询失败、权限丢失或 404 都会保留并给出提示；
- 只删除对应 Markdown，不自动删除图片，避免影响其他文章；
- 删除后仍需 `git add .`、commit 和 push，线上页面才会更新。

如果某次只想新增和更新、暂时不清理任何本地文章，可以使用 `--no-prune`。如果 Notion 页面已被彻底删除且 API 无法确认状态，脚本会保留本地文件；此时应手动删除对应 Markdown 后提交。

### 首次接管已有 Markdown

如果某篇本地文章与 Notion 输出路径相同，但没有 `notion_id`，脚本会拒绝覆盖。确认应由 Notion 接管后运行：

```bash
python3 -I tools/notion_sync.py --force
```

`--force` 只用于首次接管，不会删除其他文章。已经带有匹配 `notion_id` 的文章以后不需要该选项。

### 图片与内容支持

- Notion 上传的图片会下载到 `assets/img/posts/<slug>/`；外部图片保留原 URL。
- 单个图片上限 20 MiB，每次下载总量上限 200 MiB。
- 支持段落、标题、列表、待办、引用、Callout、Toggle、代码块、分割线、图片、书签、公式、表格和部分容器块。
- 暂未支持的块类型会明确报错，不会生成残缺文章。
- `--dry-run` 不实际下载图片，因此不会验证签名图片 URL 的可用性。

## 二、离线 ZIP 导入（备用）

适合无法使用 API 时处理**单篇文章**：

1. 在 Notion 中以整页打开文章，选择「导出 → Markdown & CSV」。
2. 运行：

```bash
python3 -I tools/notion_import.py ~/Downloads/notion-export.zip --dry-run
```

如果导出文件中没有可识别的属性，通过命令行补充：

```bash
python3 -I tools/notion_import.py ~/Downloads/notion-export.zip \
  --title "我的第一篇文章" \
  --slug my-first-post \
  --date 2026-11-17 \
  --categories "随笔" \
  --tags "Notion,Jekyll,博客" \
  --description "文章摘要" \
  --dry-run
```

3. 确认后去掉 `--dry-run`，再按上面的本地预览和 Git 发布步骤操作。

ZIP 导入结果：

```text
_posts/2026-11-17-my-first-post.md
assets/img/posts/my-first-post/...
```

可识别的文章开头属性：

```text
# 我的第一篇文章

Slug: my-first-post
Status: 待发布
Date: 2026-11-17
Categories: 随笔
Tags: Notion,Jekyll,博客
Description: 文章摘要
```

支持 `Title`、`Slug`、`Status`、`Date`、`Categories`、`Tags` 和 `Description`。命令行选项优先于导出文件；分类和标签使用中文或英文逗号分隔。

日期格式：

```text
2026-11-17
2026-11-17 20:00:00 +0800
```

只提供日期时，时间使用当天 `00:00:00 +0800`。Slug 只允许小写英文、数字和连字符。

ZIP 方案的限制：

- `--force` 只覆盖同名 Markdown，不删除旧图片。
- 只处理单篇文章；包含多份 Markdown 时会拒绝导入。
- 不下载外部图片，不执行导出文件中的任何内容。
- ZIP 解压限制为 2000 个条目、总计 200 MiB，并拦截路径穿越和符号链接。
- 不同 Notion 版本的导出格式可能变化；真实导出包首次使用时务必先运行 `--dry-run`。

## 测试

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/test_notion_import.py
PYTHONDONTWRITEBYTECODE=1 python3 -I tests/test_notion_sync.py
```
