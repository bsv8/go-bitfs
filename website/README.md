# go-bitfs documentation site

The site uses [Hugo](https://gohugo.io/), [Docsy](https://www.docsy.dev/), and [doc2go](https://abhinav.github.io/doc2go/).

- Files under `../docs` are mounted into the guide section without being copied.
- `content/reference` is generated from Go source and documentation comments by doc2go. Do not edit it.
- Tool versions are pinned in `package.json` and the `generate:api` script.

## Local preview

```bash
cd website
npm install
npm run serve
```

Open <http://localhost:1313/go-bitfs/>.

## Production build

```bash
cd website
npm ci
npm run build
```

The static site is written to `website/public`.
