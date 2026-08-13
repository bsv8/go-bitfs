# go-bitfs documentation

This site is a Docusaurus 3 documentation site. English is the normative website language at `/`; the maintained Simplified Chinese translation is at `/zh-CN/`. Translation files live only under `website/i18n/zh-CN/` and are produced and reviewed outside the production build.

The API reference is generated from the Go source by pinned `gomarkdoc` during the build and is published as native Docusaurus pages under `/api/`. Do not edit or commit `website/generated-api`, `website/build`, or `node_modules`.

## Local development

```bash
cd website
npm ci
npm run generate:api
npm run start
```

Open <http://localhost:3000/>. To preview a production build:

```bash
npm run build
npm run serve
```

## Cloudflare Pages

Use Node.js 22 and Go 1.26.0. Set Pages environment variables `NODE_VERSION=22` and `GO_VERSION=1.26.0` when the build image requires explicit versions. Set the project root to the repository root, build command to `cd website && npm ci && npm run build`, and output directory to `website/build`. Set optional `DOCS_SITE_URL` to the production custom domain; when it is unset, the Docusaurus config uses Cloudflare's `CF_PAGES_URL` automatically (and falls back to localhost only for local builds). The site uses `/` as its base URL, so no GitHub Pages sub-path is required.

## Translation workflow

Edit English Markdown under `website/docs/` first. Use an AI translation pass to update the matching files under `website/i18n/zh-CN/docusaurus-plugin-content-docs/current/`, then review protocol terms, numbers, signatures, code blocks, and links before committing. The build never calls an AI service.

Run `npm run write-translations` only to discover new Docusaurus translation IDs. The command writes source-language defaults, so review its diff and restore the maintained Chinese messages instead of accepting it as an automatic translation.
