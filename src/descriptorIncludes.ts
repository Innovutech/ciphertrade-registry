import fs from 'node:fs/promises';
import path from 'node:path';
import { canonicalMetadata } from './protocol.ts';

type Json = Record<string, unknown>;
function object(value: unknown): value is Json { return !!value && typeof value === 'object' && !Array.isArray(value); }

// ERC-7730 includes override object keys, but merge ordered fields by their path.
export function mergeDescriptor(base: unknown, override: unknown, key = ''): unknown {
  if (key === 'fields' && Array.isArray(base) && Array.isArray(override)) {
    const result = structuredClone(base);
    for (const field of override) {
      const index = object(field) && typeof field.path === 'string'
        ? result.findIndex(item => object(item) && item.path === field.path) : -1;
      if (index < 0) result.push(structuredClone(field));
      else result[index] = mergeDescriptor(result[index], field);
    }
    return result;
  }
  if (!object(base) || !object(override)) return structuredClone(override);
  const result = structuredClone(base);
  for (const [name, value] of Object.entries(override)) {
    if (['__proto__', 'prototype', 'constructor'].includes(name)) throw new Error('Unsafe descriptor key');
    result[name] = Object.hasOwn(base, name) ? mergeDescriptor(base[name], value, name) : structuredClone(value);
  }
  return result;
}

export async function resolveDescriptorIncludes(root: string, filename: string, ancestors: readonly string[] = []): Promise<Json> {
  const realRoot = await fs.realpath(root);
  const resolved = path.resolve(filename);
  const real = await fs.realpath(resolved);
  const relative = path.relative(realRoot, real);
  if (relative.startsWith('..') || path.isAbsolute(relative) || real !== resolved || !real.endsWith('.json')) throw new Error('Descriptor dependency outside source snapshot');
  if (ancestors.length >= 8 || ancestors.includes(real)) throw new Error('Cyclic or excessive descriptor includes');
  const stat = await fs.lstat(real);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 192 * 1024) throw new Error('Invalid descriptor dependency');
  const input = JSON.parse(await fs.readFile(real, 'utf8')) as unknown;
  canonicalMetadata(input);
  if (!object(input)) throw new Error('Invalid descriptor object');
  const { includes, ...own } = input;
  if (includes === undefined) return own;
  // No network dependency resolution or execution of code from source repositories.
  if (typeof includes !== 'string' || /^[a-z][a-z0-9+.-]*:/i.test(includes) || includes.includes('\\') || includes.includes('\0')) throw new Error('Unsupported descriptor include');
  const base = await resolveDescriptorIncludes(realRoot, path.resolve(path.dirname(real), includes), [...ancestors, real]);
  const merged = mergeDescriptor(base, own) as Json;
  canonicalMetadata(merged);
  return merged;
}
