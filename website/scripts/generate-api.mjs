import {mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';

await rm('generated-api', {recursive: true, force: true});
await mkdir('generated-api', {recursive: true});
await writeFile('generated-api/index.md', `---\nid: index\ntitle: API Reference\nsidebar_position: 1\n---\n\nThe API reference is generated from the exported Go packages and English doc comments before every build. It is the English source of truth; translated guides explain usage in each supported language.\n`);

const packages = ['bitfs', 'pool', 'buyer', 'seller', 'arbitration', 'wire'];
const run = (pkg) => new Promise((resolve, reject) => {
  const child = spawn('go', ['run', '-mod=mod', 'github.com/princjef/gomarkdoc/cmd/gomarkdoc@v1.1.0', '-o', `generated-api/${pkg}.md`, `github.com/bsv8/go-bitfs/${pkg}`], {stdio: 'inherit', env: {...process.env, GOWORK: 'off', GOFLAGS: ''}});
  child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`gomarkdoc failed for ${pkg} (${code})`)));
  child.on('error', reject);
});
for (const pkg of packages) {
  await run(pkg);
  const path = `generated-api/${pkg}.md`;
  const markdown = await readFile(path, 'utf8');
  // gomarkdoc emits HTML `name` anchors immediately before Markdown headings.
  // Docusaurus validates heading IDs, so move each generated name into the
  // supported explicit-heading-ID syntax and discard non-heading name anchors.
  const withHeadingIds = markdown
    .replace(/<a name="([^"]+)"><\/a>\r?\n(#{2,6} [^\n]+)/g, '$2 {#$1}')
    .replace(/<a name="[^"]+"><\/a>/g, '');
  await writeFile(path, withHeadingIds);
}
