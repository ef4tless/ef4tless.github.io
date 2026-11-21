# ef4tless.github.io

https://pwnbye4l4.com

## 从 Notion 发布

配置好本地 `.env.notion` 后，每次完整同步 Blog 数据库：发布「待发布 + 已发布」文章，并撤下已删除或转为草稿的受管文章：

```bash
python3 -I tools/notion_sync.py --dry-run
python3 -I tools/notion_sync.py
```

确认本地预览后提交并推送。Notion Integration 配置、图片处理和离线 ZIP 备用方案见 [Notion 发布工具文档](tools/README.md)。
