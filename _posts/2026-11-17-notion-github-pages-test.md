---
title: "Notion 到 GitHub Pages 发布测试"
date: 2026-11-17 19:24:00 +0800
categories: [随笔]
tags: [Notion, Jekyll, 博客]
description: "验证从 Notion 写作到 Jekyll 构建和 GitHub Pages 部署的完整流程。"
notion_id: "41b888f9-4af3-8141-bdd5-c0f42fd4aa4e"
pin: false
---

## 引言

这是一篇用于验证 **Notion → Jekyll → GitHub Pages** 完整发布流程的测试文章。

测试标识：`NOTION-JEKYLL-20261117`

> 如果这篇文章能够在线上正常访问，说明从 Notion 写作到 GitHub Pages 部署的流程已经跑通。

## 验证内容

- 在 Notion 数据库中记录标题、Slug、日期、分类和标签。
- 将 Notion 正文转换为 Jekyll Markdown 文章。
- 在本地执行 Jekyll 构建和站点检查。
- 通过 Git 提交并推送到 GitHub。
- 通过 GitHub Actions 自动构建并发布。

## 代码块测试

```bash
bundle exec jekyll build
git status --short
git push origin main
```

## 总结

Notion 负责写作，Jekyll 负责生成站点，GitHub Actions 负责自动部署。后续可以在此基础上增加导出包转换脚本，减少手动整理工作。
