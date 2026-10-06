import fs from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { verifyPrevious } from '../src/publicationLifecycle.ts';

export async function latestPublication(roots) {
  const tags = JSON.parse(execFileSync('gh', ['release', 'list', '--limit', '100', '--json', 'tagName,isDraft,isPrerelease'], { encoding: 'utf8' }));
  const tag = tags.filter(row => !row.isDraft && !row.isPrerelease && /^metadata-[1-9][0-9]*$/.test(row.tagName))
    .sort((a, b) => Number(b.tagName.slice(9)) - Number(a.tagName.slice(9)))[0]?.tagName;
  if (!tag) return null;
  const sequence = Number(tag.slice(9));
  if (!Number.isSafeInteger(sequence)) throw new Error('Invalid publication release version');
  await fs.mkdir('work/previous', { recursive: true });
  execFileSync('gh', ['release', 'download', tag, '--pattern', 'publication.json', '--dir', 'work/previous', '--clobber'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const filename = 'work/previous/publication.json';
  if ((await fs.stat(filename)).size > 64 * 1024 * 1024) throw new Error('Previous publication exceeds byte limit');
  const verified = verifyPrevious(JSON.parse(await fs.readFile(filename, 'utf8')), roots);
  if (verified.sequence !== sequence) throw new Error('Release tag and signed version disagree');
  return verified;
}
