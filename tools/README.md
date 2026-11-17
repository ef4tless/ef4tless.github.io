# Notion → Jekyll 导入工具

`notion_import.py` 将**单篇文章**的 Notion `Markdown & CSV` 导出 ZIP 转换为本站 Chirpy/Jekyll 文章，只使用 Python 标准库。

## 日常使用

1. 在 Notion 中写完文章，填写 `Title`、`Slug`、`Date`、`Categories` 和 `Tags`。
2. 确认后将 `Status` 改为 **待发布**。
3. 以整页打开该文章，选择「导出 → Markdown & CSV」，每次只导出一篇。
4. 在博客仓库中先运行 dry-run：

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

5. 确认预览后去掉 `--dry-run`，正式导入。
6. 本地检查并预览：

```bash
bundle exec jekyll serve
```

打开 `http://127.0.0.1:4000`。确认后提交：

```bash
git add .
git commit -m "Publish my-first-post"
git push origin main
```

7. 等 GitHub Actions 部署成功并检查线上页面，再将 Notion 状态改为 **已发布**。

## 导入结果

假设 `Slug` 为 `my-first-post`、日期为 `2026-11-17`：

```text
_posts/2026-11-17-my-first-post.md
assets/img/posts/my-first-post/...
```

脚本会：

- 生成 Chirpy Front Matter；
- 移除正文开头重复的一级标题和已识别的 Notion 属性行；
- 复制本地图片并改写为 `/assets/img/posts/<slug>/...`；
- 保留外部图片 URL；
- 不改写代码块或行内代码中的图片示例；
- 在缺图、无效日期、无效 Slug、多个 Markdown 文件或草稿状态下停止；
- 默认拒绝覆盖已经存在的同名文章。

## 可识别的导出属性

属性需要位于文章开头，每行一个，例如：

```text
# 我的第一篇文章

Slug: my-first-post
Status: 待发布
Date: 2026-11-17
Categories: 随笔
Tags: Notion,Jekyll,博客
Description: 文章摘要
```

支持 `Title`、`Slug`、`Status`、`Date`、`Categories`、`Tags` 和 `Description`。命令行选项优先于导出文件中的属性；分类和标签使用中文或英文逗号分隔。

日期可以写成：

```text
2026-11-17
2026-11-17 20:00:00 +0800
```

只提供日期时，时间使用当天 `00:00:00 +0800`。Slug 只允许小写英文、数字和连字符。

## 覆盖与限制

- `--force` 只覆盖同名 Markdown 文章，不删除旧图片；同名但内容不同的图片会自动使用新文件名。
- 只处理单篇文章 ZIP；数据库批量导出包含多份 Markdown 时会拒绝导入。
- 不下载外部图片，不执行导出文件中的任何内容。
- ZIP 解压限制为 2000 个条目、总计 200 MiB，并拦截路径穿越和符号链接。
- 不同 Notion 版本的导出格式可能变化；首次使用真实导出包时务必先运行 `--dry-run`。

## 测试

```bash
python3 -I tests/test_notion_import.py
```
