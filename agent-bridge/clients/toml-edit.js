// Surgical edits of one TOML table in a file that belongs to the user (Codex's .codex/config.toml).
//
// Rewriting the whole file with a TOML serializer would drop the user's comments, ordering and
// formatting, so this module finds the byte ranges of the table it owns and changes only those. The
// parser (smol-toml) is the referee: the caller verifies that the edited file still parses and that
// everything outside the owned table is semantically unchanged (verifyOnlyTableChanged).

import { parse } from "smol-toml";

export { parse };

// ---------------------------------------------------------------------------------------------
// Emitting values
// ---------------------------------------------------------------------------------------------

// A TOML basic string. Everything outside printable ASCII-or-Unicode text is \u-escaped, so no
// input (quotes, newlines, `"""`, backslashes, C0/C1 controls, line separators) can end the string
// or start a new line. Lone surrogates cannot be encoded in UTF-8 and are refused.
export function tomlString(value) {
  const s = String(value);
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) throw new Error("value contains an unpaired surrogate; refusing to write it to TOML");
      out += s[i] + s[i + 1];
      i++;
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) throw new Error("value contains an unpaired surrogate; refusing to write it to TOML");
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0d) out += "\\r";
    else if (c === 0x09) out += "\\t";
    else if (c < 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f) || c === 0x2028 || c === 0x2029 || c === 0xfeff) {
      out += "\\u" + c.toString(16).toUpperCase().padStart(4, "0");
    } else out += s[i];
  }
  return out + '"';
}

// A bare key when that is safe, a quoted key otherwise.
export const tomlKey = (k) => (/^[A-Za-z0-9_-]+$/.test(k) ? k : tomlString(k));

export const tomlArray = (items) => `[${items.map(tomlString).join(", ")}]`;

// A one-line inline table of string values.
export function tomlInlineTable(obj) {
  const pairs = Object.entries(obj).map(([k, v]) => `${tomlKey(k)} = ${tomlString(v)}`);
  return pairs.length ? `{ ${pairs.join(", ")} }` : "{}";
}

// ---------------------------------------------------------------------------------------------
// Scanning: where do tables and key/value statements start and end?
// ---------------------------------------------------------------------------------------------

// Walks the text once and returns, in order, every table header and every key/value statement with
// its byte range. Strings (including multi-line ones), arrays and inline tables are skipped as a
// whole, so a line that merely looks like `[header]` inside a value is never mistaken for one. The
// text has already been parsed by smol-toml, so it is known to be valid TOML.
export function scan(text) {
  const n = text.length;
  let i = 0;
  const items = [];
  const bad = (what) => new Error(`unexpected TOML (${what}) at offset ${i}`);

  const skipWs = () => {
    while (i < n && (text[i] === " " || text[i] === "\t")) i++;
  };
  const skipComment = () => {
    if (text[i] === "#") while (i < n && text[i] !== "\n") i++;
  };
  const skipBlank = () => {
    // whitespace, newlines and comments (inside arrays / multi-line inline tables)
    for (;;) {
      skipWs();
      if (text[i] === "\r" || text[i] === "\n") i++;
      else if (text[i] === "#") skipComment();
      else return;
    }
  };
  const endOfStatement = () => {
    skipWs();
    skipComment();
    if (text[i] === "\r") i++;
    if (i < n && text[i] === "\n") i++;
    else if (i < n) throw bad("trailing characters");
  };

  const basicString = () => {
    // at the opening quote; returns the decoded text of a single-line basic string
    i++;
    let out = "";
    while (i < n && text[i] !== '"') {
      if (text[i] === "\n") throw bad("newline in string");
      if (text[i] === "\\") {
        const e = text[i + 1];
        const simple = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\", e: "\x1b" };
        if (e in simple) {
          out += simple[e];
          i += 2;
        } else if (e === "u" || e === "U" || e === "x") {
          const len = e === "u" ? 4 : e === "U" ? 8 : 2;
          const hex = text.slice(i + 2, i + 2 + len);
          if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length !== len) throw bad("escape");
          out += String.fromCodePoint(parseInt(hex, 16));
          i += 2 + len;
        } else throw bad("escape");
      } else out += text[i++];
    }
    if (text[i] !== '"') throw bad("unterminated string");
    i++;
    return out;
  };
  const literalString = () => {
    i++;
    const start = i;
    while (i < n && text[i] !== "'" && text[i] !== "\n") i++;
    if (text[i] !== "'") throw bad("unterminated string");
    return text.slice(start, i++);
  };
  const keySegment = () => {
    if (text[i] === '"') return basicString();
    if (text[i] === "'") return literalString();
    const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 256));
    if (!m) throw bad("key");
    i += m[0].length;
    return m[0];
  };
  const key = () => {
    const segs = [];
    for (;;) {
      skipWs();
      segs.push(keySegment());
      skipWs();
      if (text[i] === ".") i++;
      else return segs;
    }
  };

  const value = () => {
    const c = text[i];
    if (text.startsWith('"""', i)) {
      i += 3;
      while (i < n) {
        if (text[i] === "\\") i += 2;
        else if (text.startsWith('"""', i)) {
          i += 3;
          while (text[i] === '"') i++; // up to two extra quotes belong to the string
          return;
        } else i++;
      }
      throw bad("unterminated multi-line string");
    }
    if (text.startsWith("'''", i)) {
      const end = text.indexOf("'''", i + 3);
      if (end < 0) throw bad("unterminated multi-line string");
      i = end + 3;
      while (text[i] === "'") i++;
      return;
    }
    if (c === '"') return void basicString();
    if (c === "'") return void literalString();
    if (c === "[") {
      i++;
      for (;;) {
        skipBlank();
        if (text[i] === "]") return void i++;
        value();
        skipBlank();
        if (text[i] === ",") i++;
      }
    }
    if (c === "{") {
      i++;
      for (;;) {
        skipBlank();
        if (text[i] === "}") return void i++;
        key();
        skipWs();
        if (text[i] !== "=") throw bad("inline table");
        i++;
        skipWs();
        value();
        skipBlank();
        if (text[i] === ",") i++;
      }
    }
    // numbers, booleans, dates: up to a delimiter (a date may contain a space)
    while (i < n && !",]}#\r\n".includes(text[i])) i++;
  };

  while (i < n) {
    skipWs();
    const c = text[i];
    if (i >= n) break;
    if (c === "\n" || c === "\r") {
      i++;
      continue;
    }
    if (c === "#") {
      skipComment();
      continue;
    }
    const start = i === 0 ? 0 : text.lastIndexOf("\n", i - 1) + 1;
    if (c === "[") {
      const array = text[i + 1] === "[";
      i += array ? 2 : 1;
      const path = key();
      skipWs();
      if (text[i] !== "]" || (array && text[i + 1] !== "]")) throw bad("table header");
      i += array ? 2 : 1;
      endOfStatement();
      items.push({ kind: "header", path, array, start, end: i });
    } else {
      const k = key();
      skipWs();
      if (text[i] !== "=") throw bad("key/value");
      i++;
      skipWs();
      value();
      endOfStatement();
      items.push({ kind: "stmt", key: k, start, end: i });
    }
  }
  return items;
}

// ---------------------------------------------------------------------------------------------
// Editing
// ---------------------------------------------------------------------------------------------

const samePath = (a, b) => a.length === b.length && a.every((s, k) => s === b[k]);
const startsWithPath = (a, b) => a.length >= b.length && b.every((s, k) => a[k] === s);

// Makes `[tablePath]` contain exactly `lines` plus whatever the user keeps there.
//   owned:  first key segments inside the table that this tool owns; those statements are removed
//           (a later `lines` entry replaces them), everything else in the table stays
//   ownedSubtables:  sub-table names (`env` for [a.b.env]) that this tool owns; those sections go
//   lines:  the new key/value lines, without line endings
// Throws if the table is defined in a form that cannot be edited piecewise (dotted keys or an inline
// table in a parent), rather than guessing.
export function replaceTable(text, tablePath, { owned, ownedSubtables, lines }) {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const items = scan(text);
  const edits = []; // { start, end, text }
  let current = [];
  let main = null;
  let firstSub = null; // start of the first kept sub-table section of ours, to insert the table before it
  const dotted = tablePath.join(".");

  // The end of a section is the start of the next header (or the end of the file).
  const sectionEnd = (idx) => {
    for (let j = idx + 1; j < items.length; j++) if (items[j].kind === "header") return items[j].start;
    return text.length;
  };

  items.forEach((it, idx) => {
    if (it.kind === "header") {
      current = it.path;
      if (!startsWithPath(it.path, tablePath)) return;
      if (it.array && it.path.length === tablePath.length) throw new Error(`${dotted} is an array of tables; init can only edit a plain [${dotted}] table.`);
      if (it.path.length === tablePath.length) main = it;
      else if (ownedSubtables.has(it.path[tablePath.length])) edits.push({ start: it.start, end: sectionEnd(idx), text: "" });
      else if (firstSub === null) firstSub = it.start;
      return;
    }
    const full = current.concat(it.key);
    // `mcp_servers = { bridge = ... }`, `bridge = { ... }` under [mcp_servers], `mcp_servers.bridge.x = ...`
    const definesFromOutside =
      (startsWithPath(full, tablePath) && current.length < tablePath.length) || (full.length < tablePath.length && startsWithPath(tablePath, full));
    if (definesFromOutside) {
      throw new Error(`${dotted} is defined with dotted keys or an inline table. Rewrite it as a [${dotted}] table (or delete it) and run init again.`);
    }
    if (samePath(current, tablePath) && owned.has(it.key[0])) edits.push({ start: it.start, end: it.end, text: "" });
  });

  if (main) {
    const atEof = main.end >= text.length && !/\n$/.test(text.slice(main.start, main.end));
    edits.push({ start: main.end, end: main.end, text: (atEof ? eol : "") + lines.map((l) => l + eol).join("") });
  } else {
    const block = `[${dotted}]${eol}${lines.map((l) => l + eol).join("")}`;
    if (firstSub !== null) edits.push({ start: firstSub, end: firstSub, text: block + eol });
    else {
      let lead = "";
      if (text.length) {
        if (!text.endsWith("\n")) lead += eol;
        if (!/(\r?\n){2}$/.test(text + lead)) lead += eol;
      }
      edits.push({ start: text.length, end: text.length, text: lead + block });
    }
  }

  // Apply from the end of the file backwards; at the same offset a deletion goes before an insertion.
  edits.sort((a, b) => b.start - a.start || b.end - a.end);
  let out = text;
  for (const e of edits) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------------------------

// A canonical string for any parsed TOML value: dates, bigints and key order cannot cause a false
// difference.
export function canon(v) {
  if (typeof v === "bigint") return `${v}n`;
  if (v instanceof Date) return `date(${typeof v.toISOString === "function" ? v.toISOString() : String(v)})`;
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? String(v);
}

const without = (obj, path) => {
  // a copy of obj with the value at `path` removed (parents copied along the way)
  if (!obj || typeof obj !== "object") return obj;
  const [head, ...rest] = path;
  if (!(head in obj)) return obj;
  const copy = { ...obj };
  if (!rest.length) delete copy[head];
  else {
    const child = without(obj[head], rest);
    // a parent that only held the removed table is not a difference (it may not exist in `before`)
    if (child && typeof child === "object" && !Array.isArray(child) && !Object.keys(child).length) delete copy[head];
    else copy[head] = child;
  }
  return copy;
};

// True when `after` equals `before` everywhere except at `tablePath` (compared on their own).
export function sameOutside(before, after, tablePath) {
  return canon(without(before, tablePath)) === canon(without(after, tablePath));
}
