#!/usr/bin/env node

/**
 * Static Site Generator for AtumBlog
 * Converts markdown pages to static HTML files
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { marked } from 'marked';
import { markedHighlight } from 'marked-highlight';
import hljs from 'highlight.js';
import yaml from 'js-yaml';
import { Feed } from 'feed';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const distDir = path.join(rootDir, 'dist');
const pagesDir = path.join(rootDir, 'pages');
const draftsDir = path.join(rootDir, 'drafts');
const templatesDir = path.join(rootDir, 'templates');
const staticDir = path.join(rootDir, 'static');

// When true, include drafts: posts under drafts/{lang}/blog/ and posts
// with `draft: true` in frontmatter. Drafts are never deployed: the
// drafts/ directory is gitignored and the production build sets this to
// false so `draft: true` posts (even accidentally committed ones) are
// stripped from the generated site.
const INCLUDE_DRAFTS = process.env.INCLUDE_DRAFTS === '1'
    || process.env.INCLUDE_DRAFTS === 'true';

// Configure marked with syntax highlighting
marked.use(markedHighlight({
    langPrefix: 'hljs language-',
    highlight(code, lang) {
        const language = hljs.getLanguage(lang) ? lang : 'plaintext';
        return hljs.highlight(code, { language }).value;
    }
}));

// Site configuration
const SITE_CONFIG = {
    title: 'atum@Tencent',
    baseUrl: 'https://a7um.github.io',
    description: {
        en: 'Personal blog about security, philosophy, and technology',
        cn: '关于安全、哲学和技术的个人博客'
    },
    author: {
        name: 'Atum',
        email: 'atum@tencent.com'
    }
};

/**
 * Parse frontmatter from markdown content
 */
function parseFrontmatter(content) {
    const frontmatterRegex = /^---\s*\r?\n([\s\S]*?)\r?\n---\s*\r?\n([\s\S]*)$/;
    const match = content.match(frontmatterRegex);
    
    if (!match) {
        throw new Error('No frontmatter found');
    }
    
    const [, frontmatterStr, markdown] = match;
    const frontmatter = yaml.load(frontmatterStr);
    
    return { frontmatter, markdown };
}

/**
 * Load template file
 */
function loadTemplate(name) {
    const templatePath = path.join(templatesDir, `${name}.html`);
    return fs.readFileSync(templatePath, 'utf8');
}

/**
 * Replace template variables
 */
function renderTemplate(template, variables) {
    let result = template;
    for (const [key, value] of Object.entries(variables)) {
        const regex = new RegExp(`{{${key}}}`, 'g');
        result = result.replace(regex, value || '');
    }
    return result;
}

/**
 * Ensure directory exists
 */
function ensureDir(dirPath) {
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
}

/**
 * Clean dist directory
 */
function cleanDist() {
    if (fs.existsSync(distDir)) {
        fs.rmSync(distDir, { recursive: true, force: true });
    }
    ensureDir(distDir);
    console.log('✓ Cleaned dist directory');
}

/**
 * Copy static assets
 */
function copyStaticAssets() {
    // Copy CSS
    const cssSource = path.join(rootDir, 'style.css');
    const cssDest = path.join(distDir, 'style.css');
    fs.copyFileSync(cssSource, cssDest);
    
    // Copy static directory
    if (fs.existsSync(staticDir)) {
        const staticDest = path.join(distDir, 'static');
        fs.cpSync(staticDir, staticDest, { recursive: true });
    }
    
    // Copy CNAME if exists
    const cnameSource = path.join(rootDir, 'CNAME');
    if (fs.existsSync(cnameSource)) {
        const cnameDest = path.join(distDir, 'CNAME');
        fs.copyFileSync(cnameSource, cnameDest);
    }
    
    // Copy .nojekyll if exists
    const nojekyllSource = path.join(rootDir, '.nojekyll');
    if (fs.existsSync(nojekyllSource)) {
        const nojekyllDest = path.join(distDir, '.nojekyll');
        fs.copyFileSync(nojekyllSource, nojekyllDest);
    }
    
    console.log('✓ Copied static assets');
}

/**
 * Coerce a frontmatter draft flag into a boolean.
 * Accepts true/false booleans and common string forms ("true", "yes", "1").
 */
function isDraftFlag(value) {
    if (value === true) return true;
    if (typeof value === 'string') {
        const v = value.trim().toLowerCase();
        return v === 'true' || v === 'yes' || v === '1';
    }
    return false;
}

/**
 * Parse a single blog post markdown file. Returns null if it should
 * be skipped (parse error or draft filtered out).
 */
function parseBlogPostFile(filePath, { isDraftSource }) {
    const file = path.basename(filePath);
    const content = fs.readFileSync(filePath, 'utf8');

    try {
        const { frontmatter, markdown } = parseFrontmatter(content);
        const id = path.basename(file, '.md');
        const draft = isDraftSource || isDraftFlag(frontmatter.draft);

        if (draft && !INCLUDE_DRAFTS) {
            console.log(`  ⏭  Skipping draft: ${file}`);
            return null;
        }

        return {
            id,
            title: frontmatter.title,
            date: frontmatter.date,
            tags: frontmatter.tags || [],
            abstract: frontmatter.abstract || '',
            markdown,
            frontmatter,
            draft
        };
    } catch (error) {
        console.error(`Error parsing ${file}:`, error.message);
        return null;
    }
}

/**
 * Parse all blog posts for a language. When INCLUDE_DRAFTS is set,
 * also merges in any posts under drafts/{lang}/blog/. Drafts override
 * published posts with the same id.
 */
function parseBlogPosts(lang) {
    const sources = [
        { dir: path.join(pagesDir, lang, 'blog'), isDraftSource: false }
    ];

    if (INCLUDE_DRAFTS) {
        sources.push({
            dir: path.join(draftsDir, lang, 'blog'),
            isDraftSource: true
        });
    }

    const byId = new Map();

    for (const { dir, isDraftSource } of sources) {
        if (!fs.existsSync(dir)) continue;

        const files = fs.readdirSync(dir);
        for (const file of files) {
            if (!file.endsWith('.md')) continue;
            const post = parseBlogPostFile(path.join(dir, file), { isDraftSource });
            if (post) byId.set(post.id, post);
        }
    }

    const posts = Array.from(byId.values());
    posts.sort((a, b) => new Date(b.date) - new Date(a.date));
    return posts;
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric' 
    });
}

/**
 * Generate blog list page
 */
function generateBlogListPage(lang, posts, allPosts) {
    const baseTemplate = loadTemplate('base');
    const listTemplate = loadTemplate('blog-list');
    
    const langName = lang === 'en' ? 'English' : '中文';
    const otherLang = lang === 'en' ? 'cn' : 'en';
    
    // Get all unique tags
    const allTags = new Set();
    posts.forEach(post => {
        post.tags.forEach(tag => allTags.add(tag));
    });
    const sortedTags = Array.from(allTags).sort();
    
    // Generate tag filter HTML
    const allText = 'All';
    const tagFilterHTML = sortedTags.length > 0 ? `
        <div class="prompt-line">
            <span class="prompt">atum@Tencent % </span>
            <span class="command">ls tags</span>
        </div>
        <div class="tag-filter-container">
            <span class="filter-tag active" data-tag=""><a href="/${lang}/" style="color: inherit; text-decoration: none;">${allText}</a></span>
            ${sortedTags.map(tag => 
                `<span class="filter-tag" data-tag="${tag}"><a href="/${lang}/tag/${encodeURIComponent(tag)}/" style="color: inherit; text-decoration: none;">${tag}</a></span>`
            ).join('\n            ')}
        </div>
    ` : '';
    
    // Generate blog list prompt
    const blogListPrompt = `
        <div class="prompt-line">
            <span class="prompt">atum@Tencent % </span>
            <span class="command">ls -l</span>
        </div>
    `;
    
    // Generate blog items HTML in SPA format
    const blogItems = posts.map(post => {
        const tagsHTML = post.tags.map((tag, index) => {
            const separator = index < post.tags.length - 1 ? ', ' : '';
            return `<span class="tag" data-tag="${tag}"><a href="/${lang}/tag/${encodeURIComponent(tag)}/">${tag}</a></span>${separator}`;
        }).join('');
        
        return `
            <div class="blog-entry">
                <div class="blog-header" data-post-id="${post.id}">
                    ==&gt; atum, ${formatDate(post.date)}, [${tagsHTML}], <a href="/${lang}/blog/${post.id}/" style="color: inherit; text-decoration: none;">${post.title}</a> &lt;==
                </div>
                <div class="blog-abstract">${post.abstract}</div>
            </div>`;
    }).join('\n');
    
    const listContent = renderTemplate(listTemplate, {
        TAG_FILTER: tagFilterHTML,
        BLOG_LIST_PROMPT: blogListPrompt,
        BLOG_ITEMS: blogItems
    });
    
    const html = renderTemplate(baseTemplate, {
        LANG: lang,
        LANG_NAME: langName,
        TITLE: `${SITE_CONFIG.title} - Blog`,
        META_DESCRIPTION: SITE_CONFIG.description[lang],
        CANONICAL_URL: `${SITE_CONFIG.baseUrl}/${lang}/`,
        EN_URL: '/en/',
        CN_URL: '/cn/',
        OG_TYPE: 'website',
        EXTRA_HEAD: '',
        BLOGS_ACTIVE: 'active',
        BLOGS_INDICATOR: '*',
        PORTFOLIO_ACTIVE: '',
        PORTFOLIO_INDICATOR: '-',
        ABOUT_ACTIVE: '',
        ABOUT_INDICATOR: '-',
        EN_LANG_ACTIVE: lang === 'en' ? 'active' : '',
        CN_LANG_ACTIVE: lang === 'cn' ? 'active' : '',
        COMMAND: '',
        CONTENT: listContent,
        EXTRA_SCRIPTS: ''
    });
    
    const outputPath = path.join(distDir, lang, 'index.html');
    ensureDir(path.dirname(outputPath));
    fs.writeFileSync(outputPath, html);
    
    console.log(`✓ Generated blog list: /${lang}/`);
}

/**
 * Strip H1 headings from markdown content
 * @param {string} markdown - Markdown content
 * @returns {string} Markdown without H1 headings
 */
function stripH1FromMarkdown(markdown) {
    // Remove H1 headings (# Title or Title\n===)
    return markdown
        .replace(/^#\s+.+$/gm, '') // Remove # style H1
        .replace(/^.+\n=+\s*$/gm, '') // Remove === style H1
        .trim();
}

/**
 * Check if math content exists in markdown
 */
function hasMathContent(markdown) {
    return /\$\$|\\\(|\\\[/.test(markdown);
}

/**
 * Generate individual blog post page
 */
function generateBlogPostPage(lang, post, allPosts) {
    const baseTemplate = loadTemplate('base');
    const postTemplate = loadTemplate('blog-post');
    
    const langName = lang === 'en' ? 'English' : '中文';
    const otherLang = lang === 'en' ? 'cn' : 'en';
    
    // Find corresponding post in other language
    const otherLangPosts = allPosts[otherLang];
    const correspondingPost = otherLangPosts.find(p => p.id === post.id);
    const otherLangUrl = correspondingPost 
        ? `/${otherLang}/blog/${post.id}/`
        : `/${otherLang}/`;
    
    // Strip H1 from markdown and render to HTML
    const markdownWithoutH1 = stripH1FromMarkdown(post.markdown);
    const contentHtml = marked.parse(markdownWithoutH1);
    
    // Generate tags HTML
    const tagsHtml = post.tags.map(tag => 
        `<span class="tag"><a href="/${lang}/tag/${encodeURIComponent(tag)}/">${tag}</a></span>`
    ).join(' ');
    
    const postContent = renderTemplate(postTemplate, {
        POST_ID: post.id,
        POST_TITLE: post.title,
        POST_DATE: formatDate(post.date),
        POST_TAGS: tagsHtml,
        POST_CONTENT: contentHtml,
        LANG: lang
    });
    
    // Add MathJax if needed
    const extraHead = hasMathContent(post.markdown) ? `
    <script>
        window.MathJax = {
            tex: {
                inlineMath: [['\\\\(', '\\\\)']],
                displayMath: [['$$', '$$']],
                processEscapes: true
            },
            options: {
                skipHtmlTags: ['script', 'noscript', 'style', 'textarea', 'pre']
            }
        };
    </script>
    <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    ` : `
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    `;
    
    const html = renderTemplate(baseTemplate, {
        LANG: lang,
        LANG_NAME: langName,
        TITLE: `${post.title} - ${SITE_CONFIG.title}`,
        META_DESCRIPTION: post.abstract || post.title,
        CANONICAL_URL: `${SITE_CONFIG.baseUrl}/${lang}/blog/${post.id}/`,
        EN_URL: lang === 'en' ? `/${lang}/blog/${post.id}/` : otherLangUrl,
        CN_URL: lang === 'cn' ? `/${lang}/blog/${post.id}/` : otherLangUrl,
        OG_TYPE: 'article',
        EXTRA_HEAD: extraHead,
        BLOGS_ACTIVE: 'active',
        BLOGS_INDICATOR: '*',
        PORTFOLIO_ACTIVE: '',
        PORTFOLIO_INDICATOR: '-',
        ABOUT_ACTIVE: '',
        ABOUT_INDICATOR: '-',
        EN_LANG_ACTIVE: lang === 'en' ? 'active' : '',
        CN_LANG_ACTIVE: lang === 'cn' ? 'active' : '',
        COMMAND: `cat blog/${post.id}.md`,
        CONTENT: postContent,
        EXTRA_SCRIPTS: ''
    });
    
    const outputPath = path.join(distDir, lang, 'blog', post.id, 'index.html');
    ensureDir(path.dirname(outputPath));
    fs.writeFileSync(outputPath, html);
    
    console.log(`✓ Generated blog post: /${lang}/blog/${post.id}/`);
}

/**
 * Generate tag page
 */
function generateTagPage(lang, tag, posts) {
    const baseTemplate = loadTemplate('base');
    const listTemplate = loadTemplate('blog-list');
    
    const langName = lang === 'en' ? 'English' : '中文';
    const otherLang = lang === 'en' ? 'cn' : 'en';
    
    const taggedPosts = posts.filter(post => post.tags.includes(tag));
    
    // Get all unique tags for filter display
    const allTags = new Set();
    posts.forEach(post => {
        post.tags.forEach(t => allTags.add(t));
    });
    const sortedTags = Array.from(allTags).sort();
    
    // Generate tag filter HTML with current tag active
    const allText = 'All';
    const tagFilterHTML = `
        <div class="prompt-line">
            <span class="prompt">atum@Tencent % </span>
            <span class="command">ls tags</span>
        </div>
        <div class="tag-filter-container">
            <span class="filter-tag" data-tag=""><a href="/${lang}/" style="color: inherit; text-decoration: none;">${allText}</a></span>
            ${sortedTags.map(t => {
                const isActive = t === tag;
                return `<span class="filter-tag ${isActive ? 'active' : ''}" data-tag="${t}">
                    <a href="/${lang}/tag/${encodeURIComponent(t)}/" style="color: inherit; text-decoration: none;">${t}</a>
                </span>`;
            }).join('\n            ')}
        </div>
    `;
    
    // Generate blog list prompt with tag filter
    const blogListPrompt = `
        <div class="prompt-line">
            <span class="prompt">atum@Tencent % </span>
            <span class="command">ls -l | grep ${tag}</span>
        </div>
    `;
    
    // Generate blog items in SPA format
    const blogItems = taggedPosts.map(post => {
        const tagsHTML = post.tags.map(t => 
            `<span class="tag" data-tag="${t}">${t}</span>`
        ).join(', ');
        
        return `
            <div class="blog-entry">
                <div class="blog-header" data-post-id="${post.id}">
                    <a href="/${lang}/blog/${post.id}/" style="color: inherit; text-decoration: none;">==> atum, ${formatDate(post.date)}, [${tagsHTML}], ${post.title} &lt;==</a>
                </div>
                <div class="blog-abstract">${post.abstract}</div>
            </div>`;
    }).join('\n');
    
    const listContent = renderTemplate(listTemplate, {
        TAG_FILTER: tagFilterHTML,
        BLOG_LIST_PROMPT: blogListPrompt,
        BLOG_ITEMS: blogItems
    });
    
    const html = renderTemplate(baseTemplate, {
        LANG: lang,
        LANG_NAME: langName,
        TITLE: `${tag} - ${SITE_CONFIG.title}`,
        META_DESCRIPTION: `Blog posts tagged with ${tag}`,
        CANONICAL_URL: `${SITE_CONFIG.baseUrl}/${lang}/tag/${encodeURIComponent(tag)}/`,
        EN_URL: `/${lang}/tag/${encodeURIComponent(tag)}/`,
        CN_URL: `/${otherLang}/tag/${encodeURIComponent(tag)}/`,
        OG_TYPE: 'website',
        EXTRA_HEAD: '',
        BLOGS_ACTIVE: 'active',
        BLOGS_INDICATOR: '*',
        PORTFOLIO_ACTIVE: '',
        PORTFOLIO_INDICATOR: '-',
        ABOUT_ACTIVE: '',
        ABOUT_INDICATOR: '-',
        EN_LANG_ACTIVE: lang === 'en' ? 'active' : '',
        CN_LANG_ACTIVE: lang === 'cn' ? 'active' : '',
        COMMAND: '',
        CONTENT: listContent,
        EXTRA_SCRIPTS: ''
    });
    
    const outputPath = path.join(distDir, lang, 'tag', encodeURIComponent(tag), 'index.html');
    ensureDir(path.dirname(outputPath));
    fs.writeFileSync(outputPath, html);
}

/**
 * Generate static page (about, portfolio)
 */
function generateStaticPage(lang, pageName) {
    const baseTemplate = loadTemplate('base');
    const staticTemplate = loadTemplate('static-page');
    
    const langName = lang === 'en' ? 'English' : '中文';
    const otherLang = lang === 'en' ? 'cn' : 'en';
    
    const pagePath = path.join(pagesDir, lang, `${pageName}.md`);
    
    if (!fs.existsSync(pagePath)) {
        console.log(`⚠ Static page not found: ${pagePath}`);
        return;
    }
    
    const content = fs.readFileSync(pagePath, 'utf8');
    const contentHtml = marked.parse(content);
    
    const tabConfig = {
        about: { active: 'ABOUT', command: 'cat about.md' },
        portfolio: { active: 'PORTFOLIO', command: 'cat portfolio.md' }
    };
    
    const config = tabConfig[pageName];
    
    const pageContent = renderTemplate(staticTemplate, {
        COMMAND: config.command,
        PAGE_CONTENT: contentHtml
    });
    
    const html = renderTemplate(baseTemplate, {
        LANG: lang,
        LANG_NAME: langName,
        TITLE: `${pageName.charAt(0).toUpperCase() + pageName.slice(1)} - ${SITE_CONFIG.title}`,
        META_DESCRIPTION: SITE_CONFIG.description[lang],
        CANONICAL_URL: `${SITE_CONFIG.baseUrl}/${lang}/${pageName}/`,
        EN_URL: `/en/${pageName}/`,
        CN_URL: `/cn/${pageName}/`,
        OG_TYPE: 'website',
        EXTRA_HEAD: '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">',
        BLOGS_ACTIVE: config.active === 'BLOGS' ? 'active' : '',
        BLOGS_INDICATOR: config.active === 'BLOGS' ? '*' : '-',
        PORTFOLIO_ACTIVE: config.active === 'PORTFOLIO' ? 'active' : '',
        PORTFOLIO_INDICATOR: config.active === 'PORTFOLIO' ? '*' : '-',
        ABOUT_ACTIVE: config.active === 'ABOUT' ? 'active' : '',
        ABOUT_INDICATOR: config.active === 'ABOUT' ? '*' : '-',
        EN_LANG_ACTIVE: lang === 'en' ? 'active' : '',
        CN_LANG_ACTIVE: lang === 'cn' ? 'active' : '',
        COMMAND: config.command,
        CONTENT: pageContent,
        EXTRA_SCRIPTS: ''
    });
    
    const outputPath = path.join(distDir, lang, pageName, 'index.html');
    ensureDir(path.dirname(outputPath));
    fs.writeFileSync(outputPath, html);
    
    console.log(`✓ Generated static page: /${lang}/${pageName}/`);
}

/**
 * Generate RSS feed
 */
function generateRSSFeed(lang, posts) {
    const langName = lang === 'en' ? 'English' : '中文';
    
    const feed = new Feed({
        title: `${SITE_CONFIG.title} - ${langName}`,
        description: SITE_CONFIG.description[lang],
        id: `${SITE_CONFIG.baseUrl}/${lang}/`,
        link: `${SITE_CONFIG.baseUrl}/${lang}/`,
        language: lang === 'en' ? 'en' : 'zh',
        favicon: `${SITE_CONFIG.baseUrl}/favicon.ico`,
        copyright: `Copyright © ${new Date().getFullYear()} ${SITE_CONFIG.author.name}`,
        feedLinks: {
            rss: `${SITE_CONFIG.baseUrl}/rss-${lang}.xml`
        },
        author: {
            name: SITE_CONFIG.author.name,
            email: SITE_CONFIG.author.email
        }
    });
    
    posts.forEach(post => {
        feed.addItem({
            title: post.title,
            id: `${SITE_CONFIG.baseUrl}/${lang}/blog/${post.id}/`,
            link: `${SITE_CONFIG.baseUrl}/${lang}/blog/${post.id}/`,
            description: post.abstract,
            content: marked.parse(post.markdown),
            date: new Date(post.date),
            category: post.tags.map(tag => ({ name: tag }))
        });
    });
    
    const rssPath = path.join(distDir, `rss-${lang}.xml`);
    fs.writeFileSync(rssPath, feed.rss2());
    
    console.log(`✓ Generated RSS feed: /rss-${lang}.xml`);
}

/**
 * Generate sitemap
 */
function generateSitemap(allPosts) {
    const urls = [];
    
    // Add home pages
    urls.push({ url: '/en/', priority: 1.0 });
    urls.push({ url: '/cn/', priority: 1.0 });
    
    // Add static pages
    ['about', 'portfolio'].forEach(page => {
        urls.push({ url: `/en/${page}/`, priority: 0.8 });
        urls.push({ url: `/cn/${page}/`, priority: 0.8 });
    });
    
    // Add blog posts
    ['en', 'cn'].forEach(lang => {
        allPosts[lang].forEach(post => {
            urls.push({
                url: `/${lang}/blog/${post.id}/`,
                lastmod: post.date,
                priority: 0.7
            });
        });
        
        // Add tag pages
        const allTags = new Set();
        allPosts[lang].forEach(post => {
            post.tags.forEach(tag => allTags.add(tag));
        });
        
        allTags.forEach(tag => {
            urls.push({
                url: `/${lang}/tag/${encodeURIComponent(tag)}/`,
                priority: 0.5
            });
        });
    });
    
    const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(({ url, lastmod, priority }) => `  <url>
    <loc>${SITE_CONFIG.baseUrl}${url}</loc>
    ${lastmod ? `<lastmod>${lastmod}</lastmod>` : ''}
    <priority>${priority}</priority>
  </url>`).join('\n')}
</urlset>`;
    
    const sitemapPath = path.join(distDir, 'sitemap.xml');
    fs.writeFileSync(sitemapPath, sitemap);
    
    console.log('✓ Generated sitemap.xml');
}

/**
 * Generate language detection root index
 */
function generateRootIndex() {
    const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirecting...</title>
    <script>
        const browserLang = navigator.language || navigator.userLanguage;
        const lang = browserLang.startsWith('zh') ? 'cn' : 'en';
        window.location.replace('/' + lang + '/');
    </script>
    <meta http-equiv="refresh" content="0; url=/en/">
</head>
<body>
    <p>Redirecting...</p>
</body>
</html>`;
    
    const indexPath = path.join(distDir, 'index.html');
    fs.writeFileSync(indexPath, html);
    
    console.log('✓ Generated root index.html with language detection');
}

/**
 * Main build function
 */
async function build() {
    console.log('🔨 Building static site...\n');

    if (INCLUDE_DRAFTS) {
        console.log('📝 INCLUDE_DRAFTS=1 — drafts will be included in this build');
        console.log('   (do NOT deploy this output)\n');
    }

    // Clean and prepare
    cleanDist();
    copyStaticAssets();
    
    // Parse all posts
    const allPosts = {
        en: parseBlogPosts('en'),
        cn: parseBlogPosts('cn')
    };
    
    console.log(`\nFound ${allPosts.en.length} English posts and ${allPosts.cn.length} Chinese posts\n`);
    
    // Generate pages for each language
    for (const lang of ['en', 'cn']) {
        const posts = allPosts[lang];
        
        // Generate blog list
        generateBlogListPage(lang, posts, allPosts);
        
        // Generate individual blog posts
        for (const post of posts) {
            generateBlogPostPage(lang, post, allPosts);
        }
        
        // Generate tag pages
        const allTags = new Set();
        posts.forEach(post => {
            post.tags.forEach(tag => allTags.add(tag));
        });
        
        for (const tag of allTags) {
            generateTagPage(lang, tag, posts);
        }
        
        console.log(`✓ Generated ${allTags.size} tag pages for ${lang}`);
        
        // Generate static pages
        generateStaticPage(lang, 'about');
        generateStaticPage(lang, 'portfolio');
        
        // Generate RSS feed
        generateRSSFeed(lang, posts);
    }
    
    // Generate sitemap
    generateSitemap(allPosts);
    
    // Generate root index with language detection
    generateRootIndex();
    
    console.log('\n✅ Static site generation complete!');
    console.log(`📁 Output directory: ${distDir}`);
    console.log('\n💡 Test locally with: npm run serve-dist');
}

// Run build
build().catch(error => {
    console.error('❌ Build failed:', error);
    process.exit(1);
});
