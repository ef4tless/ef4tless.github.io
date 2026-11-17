# ef4tless.github.io

https://ef4tless.github.io

## 从 Notion 发布

将单篇文章的 Notion `Markdown & CSV` 导出 ZIP 导入 Jekyll：

```bash
python3 -I tools/notion_import.py ~/Downloads/notion-export.zip --dry-run
```

确认后去掉 `--dry-run` 正式导入。属性补充、图片处理、本地预览和发布步骤见 [Notion 导入工具文档](tools/README.md)。
