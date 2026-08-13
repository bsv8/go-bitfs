import {rm} from 'node:fs/promises';
for (const path of ['build', '.docusaurus', 'generated-api']) {
  await rm(path, {recursive: true, force: true});
}
