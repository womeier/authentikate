import { readFileSync } from 'node:fs';

const common = readFileSync(new URL('./common.wat', import.meta.url), 'utf8');

// Balanced function extraction ignores strings and both WAT comment forms.
function form(source, start) {
  let depth = 0, comment = 0, quoted = false;
  for (let i = start; i < source.length; i++) {
    const pair = source.slice(i, i + 2), c = source[i];
    if (comment) {
      if (pair === '(;') { comment++; i++; }
      else if (pair === ';)') { comment--; i++; }
    } else if (quoted) {
      if (c === '\\') i++;
      else if (c === '"') quoted = false;
    } else if (pair === ';;') {
      i = source.indexOf('\n', i);
      if (i < 0) break;
    } else if (pair === '(;') { comment++; i++; }
    else if (c === '"') quoted = true;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return source.slice(start, i + 1);
  }
  throw new Error('Unbalanced WAT form');
}

// Templates explicitly select helpers; no adapter is a source for another.
export function expandAdapter(source) {
  return source.replace(/;; @COMMON ([^@\n]+)@/g, (_, names) =>
    names.trim().split(/\s+/).map(name => {
      const start = common.indexOf(`(func $${name} `);
      if (start < 0) throw new Error(`Missing common WAT helper ${name}`);
      return form(common, start);
    }).join('\n  '));
}
