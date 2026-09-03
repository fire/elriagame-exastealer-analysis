#!/usr/bin/env node
// peel_launcher.js — decrypt the nested obfuscation layers of
// resources/app.asar/launcher1.js from the Exastealer / "ElriaGame" dropper.
//
// Usage:
//   node peel_launcher.js <launcher1.js> [out_dir]
//
// The stub at every layer is identical in shape:
//
//   var _d = "<base64>";
//   var _k = "<64-char hex string>";
//   var _r = <int>;
//   var _f = function(d, k, r) {
//     var b  = Buffer.from(d, 'base64');
//     var kb = Buffer.from(k, 'utf8');   // note: hex string used as UTF-8 bytes
//     for (var i = 0; i < b.length; i++) {
//       b[i] = (((b[i] - r - i) ^ kb[(i + r) % kb.length]) & 0xFF);
//     }
//     return b.toString('utf8');
//   };
//   eval(_f(_d, _k, _r));
//
// This tool writes every intermediate stage to disk. It never calls eval.
// The sample this was written against exposes 4 layers.

'use strict';

const fs   = require('fs');
const path = require('path');

function decode(d, k, r) {
  const b  = Buffer.from(d, 'base64');
  const kb = Buffer.from(k, 'utf8');
  for (let i = 0; i < b.length; i++) {
    b[i] = (((b[i] - r - i) ^ kb[(i + r) % kb.length]) & 0xff);
  }
  return b.toString('utf8');
}

function peel(source) {
  // Match: var A = "<base64>"; var B = "<hex>"; var C = <int>;
  // Identifiers may contain $, and the strings may be very long.
  const re = /var\s+[\w$]+\s*=\s*"([A-Za-z0-9+/=]{200,})";\s*var\s+[\w$]+\s*=\s*"([0-9a-f]{40,80})";\s*var\s+[\w$]+\s*=\s*(\d+);/;
  const m = source.match(re);
  if (!m) return null;
  return { text: decode(m[1], m[2], parseInt(m[3], 10)), rot: parseInt(m[3], 10), key: m[2] };
}

function main() {
  const [, , input, outDirArg] = process.argv;
  if (!input) {
    console.error('usage: node peel_launcher.js <launcher1.js> [out_dir]');
    process.exit(2);
  }
  const outDir = outDirArg || path.dirname(input);
  fs.mkdirSync(outDir, { recursive: true });

  let text = fs.readFileSync(input, 'utf8');
  let layer = 0;
  while (layer < 25) {
    const peeled = peel(text);
    if (!peeled) break;
    layer++;
    text = peeled.text;
    const p = path.join(outDir, `stage-${layer}.js`);
    fs.writeFileSync(p, text);
    console.log(`layer ${layer}  size=${text.length}  r=${peeled.rot}  k=${peeled.key.slice(0, 10)}...  -> ${p}`);
  }
  const finalPath = path.join(outDir, 'final.js');
  fs.writeFileSync(finalPath, text);
  console.log(`final size ${text.length}  layers=${layer}  -> ${finalPath}`);
}

main();
