# AtumBlog - Static Site Generator

A tmux-styled blog generated as a static site.

## Features

- 🌐 **Fully Static**: All pages pre-rendered to HTML during build
- 🔄 **Automatic Language Detection**: Detects browser language (Chinese/English)
- 📝 **Markdown Support**: Write posts in Markdown with frontmatter
- 🎨 **Terminal UI**: Tmux-inspired interface
- 🔍 **SEO Optimized**: Proper meta tags, sitemap, and RSS feeds
- 📱 **Responsive**: Works on all devices
- ⚡ **Fast**: No client-side routing needed

## Project Structure

```
├── pages/              # Markdown content
│   ├── en/            # English content
│   │   ├── blog/      # Blog posts
│   │   ├── about.md   # About page
│   │   └── portfolio.md
│   └── cn/            # Chinese content
│       └── ...
├── scripts/           # Build scripts
│   ├── generate-static-site.js  # Main static site generator
│-- templates/     # HTML templates
│   ├── base.html
│   ├── blog-item.html
│   ├── blog-list.html
│   ├── blog-post.html
│   ├── static-page.html 
│   └── tag-filter.html
├── static/            # Static assets (images, etc.)
├── style.css          # Styles
└── dist/              # Generated static site (gitignored)
```

## Build Process

### Local Development

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Generate static site:**
   ```bash
   npm run build-static
   ```

3. **Serve locally:**
   ```bash
   npm run serve-dist
   ```
   Then open http://localhost:8000

### Production Build

The site is automatically built and deployed via GitHub Actions on push to `main`:

```yaml
- npm run build-static  # Generates dist/ directory
- Upload dist/ to GitHub Pages
```

## Writing Content

### Blog Posts

Create a markdown file in `pages/{lang}/blog/`:

```markdown
---
title: Your Post Title
date: 2025-01-15
tags: [tag1, tag2]
abstract: Brief description of the post
---

Your content here...
```

### Drafts (never published, never pushed)

When you start a new post and are not ready to share it — not even on a
feature branch — keep it out of `pages/` so it is never committed.

There are two supported workflows:

**1. Local-only drafts folder (recommended)**

Put work-in-progress posts under `drafts/{lang}/blog/`. This folder is
listed in `.gitignore`, so nothing inside it is ever tracked by git,
committed, or pushed to any branch/remote.

```
drafts/
├── en/
│   └── blog/
│       └── my-new-post.md
└── cn/
    └── blog/
        └── my-new-post.md
```

To preview drafts locally together with the published posts:

```bash
npm run preview-drafts   # build with INCLUDE_DRAFTS=1, then serve on :8000
# or, just build:
npm run build-drafts
```

The production GitHub Actions deploy job runs `npm run build-static`
without `INCLUDE_DRAFTS`, so drafts can never reach GitHub Pages.

When a draft is ready, move the file from `drafts/{lang}/blog/` to
`pages/{lang}/blog/` and commit it normally.

**2. `draft: true` frontmatter flag**

If you prefer to keep a draft alongside published posts in `pages/`,
add `draft: true` to its frontmatter:

```markdown
---
title: Work In Progress
date: 2026-04-21
tags: [wip]
abstract: Not ready yet.
draft: true
---
```

Posts with `draft: true` are stripped from normal builds (and therefore
from deploys) and are only rendered when `INCLUDE_DRAFTS=1` is set.
Note: this option *does* place the file in git if you commit it, so use
option 1 if you want the draft to stay completely off any branch.

### Static Pages

Create markdown files:
- `pages/{lang}/about.md`
- `pages/{lang}/portfolio.md`

## Generated Output

The build process creates:

```
dist/
├── index.html          # Language detector
├── en/
│   ├── index.html      # Blog list
│   ├── about/
│   │   └── index.html
│   ├── portfolio/
│   │   └── index.html
│   ├── blog/
│   │   ├── post-slug/
│   │   │   └── index.html
│   │   └── ...
│   └── tag/
│       ├── tag-name/
│       │   └── index.html
│       └── ...
├── cn/
│   └── ... (same structure)
├── sitemap.xml
├── rss-en.xml
├── rss-cn.xml
└── style.css
```

## Deployment

Deployed automatically to GitHub Pages via GitHub Actions when pushing to `main`.

Live site: https://a7um.github.io (or your custom domain)

## License

MIT
