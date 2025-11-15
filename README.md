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
