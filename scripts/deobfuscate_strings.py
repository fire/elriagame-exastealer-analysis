#!/usr/bin/env python3
"""Exastealer deobfuscator v6 — name-agnostic + correct enclosing tracker."""
import json, re, sys, pathlib, time

ROOT = pathlib.Path(sys.argv[1])
TABLES = json.loads((ROOT / 'work' / 'tables2.json').read_text())
SRC = ROOT / 'decomp-vf' / 'com' / 'xc17edb19a'
DST = ROOT / 'decomp-decrypted' / 'com' / 'xc17edb19a'
DST.mkdir(parents=True, exist_ok=True)

def jh(s):
    h = 0
    for ch in s: h = (31 * h + ord(ch)) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h
def i32(x):
    x &= 0xFFFFFFFF; return x - 0x100000000 if x >= 0x80000000 else x
def ashr(x, n): return i32(i32(x) >> n)

def parse_char_lit(s):
    if s.startswith('\\u'): return int(s[2:], 16)
    m = {"\\'": 39, "\\\\": 92, "\\n": 10, "\\r": 13, "\\t": 9,
         "\\0": 0, "\\b": 8, "\\f": 12, '\\"': 34}
    if s in m: return m[s]
    return ord(s)

METHOD_SIG_RE = re.compile(
    r'(private\s+static\s+(String|int)\s+([a-zA-Z_$][\w$]*)\s*\(int\s+var\d+,\s*int\s+var\d+(?:,\s*char\s+var\d+)?\)\s*\{)'
)

def parse_methods(src):
    out = []
    for mm in METHOD_SIG_RE.finditer(src):
        pos = mm.start()
        ret = mm.group(2); name = mm.group(3)
        is3 = ', char var' in mm.group(1)
        start = mm.end()
        end_m = re.search(r'^\s{3}\}$', src[start:], re.MULTILINE)
        body = src[start:start + end_m.start()] if end_m else src[start:start+4000]
        info = {'name': name, 'return': ret, 'kind': None, 'pos': pos}
        if ret == 'int':
            m = re.search(r'return\s+([a-zA-Z_$][\w$]*)\[var\d+\s*\^\s*(-?\d+)\]\s*\^\s*var\d+\s*\^\s*var\d+;', body)
            if m: info.update(kind='X', table_field=m.group(1), X_INDEX_MAGIC=int(m.group(2)))
        elif ret == 'String':
            if is3:
                m = re.search(r"int\s+var\d+\s*=\s*var2\s*\^\s*'((?:\\u[0-9a-fA-F]{4}|\\.|.))';", body)
                if not m: continue
                info.update(kind='K3', K_INDEX_CHAR_MAGIC=parse_char_lit(m.group(1)))
                mt = re.search(r'char\[\]\s+var\d+\s*=\s*([a-zA-Z_$][\w$]*)\[var\d+\]\.toCharArray\(\);', body)
                if mt: info['table_field'] = mt.group(1)
                mch = re.search(r'\.getMethodName\(\)\.hashCode\(\)\)\s*>>\s*16\s*\^\s*(-?\d+);', body)
                if mch: info['CALLER_HASH_MAGIC'] = int(mch.group(1))
                init = re.search(r"int\s+var(\d+)\s*=\s*[a-zA-Z_$][\w$]*\[var\d+\]\s*(\+|\^)\s*(?:(-?\d+)|'((?:\\u[0-9a-fA-F]{4}|\\.|.))');", body)
                if not init: continue
                init_op = 'add' if init.group(2) == '+' else 'xor'
                init_val = int(init.group(3)) if init.group(3) is not None else parse_char_lit(init.group(4))
                ops = [(init_op, init_val)]
                vn = 'var' + init.group(1)
                for om in re.finditer(re.escape(vn) + r"\s*(\^|\+)=\s*(?:(-?\d+)|'((?:\\u[0-9a-fA-F]{4}|\\.|.))');", body):
                    op = 'xor' if om.group(1) == '^' else 'add'
                    val = int(om.group(2)) if om.group(2) is not None else parse_char_lit(om.group(3))
                    ops.append((op, val))
                info['PRECHAIN_OPS'] = ops
                # Which int arg is direct, which is shifted?
                fm = re.search(r"var\d+\[var\d+\]\s*=\s*\(char\)\(var\d+\s*\^\s*var\d+\s*\^\s*(var[01])\s*\^\s*(var[01])\s*>>\s*16\)", body)
                if fm:
                    info['DIRECT_ARG'] = fm.group(1)   # 'var0' or 'var1'
                    info['SHIFT_ARG']  = fm.group(2)
                else:
                    info['DIRECT_ARG'] = 'var0'; info['SHIFT_ARG'] = 'var1'
            else:
                m = re.search(r'int\s+var\d+\s*=\s*var0\s*\^\s*(-?\d+);', body)
                if not m: continue
                info.update(kind='K2', K_INDEX_MAGIC=int(m.group(1)))
                mt = re.search(r'char\[\]\s+var\d+\s*=\s*([a-zA-Z_$][\w$]*)\[var\d+\]\.toCharArray\(\);', body)
                if mt: info['table_field'] = mt.group(1)
                mch = re.search(r'\.getMethodName\(\)\.hashCode\(\)\)\s*>>\s*16\s*\^\s*(-?\d+);', body)
                if mch: info['CALLER_HASH_MAGIC'] = int(mch.group(1))
                tbl = {}
                for cm in re.finditer(r'(default|case (\d+))\s*->\s*(-?\d+)', body):
                    v = int(cm.group(3))
                    if cm.group(1) == 'default': tbl.setdefault(0, v)
                    else: tbl[int(cm.group(2))] = v
                if len(tbl) >= 32:
                    info['XOR_TABLE'] = [tbl.get(i, tbl[0]) for i in range(32)]
        if info.get('kind'): out.append(info)
    return out

def dec_K2(arr, info, a, b, cls_fqn, meth):
    idx = i32(a ^ info['K_INDEX_MAGIC'])
    ct = arr[idx]
    ck = i32(ashr(jh(cls_fqn) ^ jh(meth), 16) ^ info['CALLER_HASH_MAGIC'])
    bs = ashr(b, 16)
    return ''.join(chr(ord(c) ^ (i32(info['XOR_TABLE'][i & 31] ^ bs ^ ck) & 0xFFFF)) for i, c in enumerate(ct))

def dec_K3(arr, info, a, b, cc, cls_fqn, meth):
    idx = i32(cc ^ info['K_INDEX_CHAR_MAGIC'])
    ct = arr[idx]
    ck = i32(ashr(jh(cls_fqn) ^ jh(meth), 16) ^ info['CALLER_HASH_MAGIC'])
    direct = a if info.get('DIRECT_ARG','var0') == 'var0' else b
    shift  = ashr(a if info.get('SHIFT_ARG','var1') == 'var0' else b, 16)
    out = []
    for c in ct:
        v = ord(c)
        for op, imm in info['PRECHAIN_OPS']:
            if op == 'xor': v ^= imm
            else:            v = (v + imm) & 0xFFFFFFFF
        out.append(chr(i32(v ^ ck ^ direct ^ shift) & 0xFFFF))
    return ''.join(out)

def dec_X(arr, info, a, b):
    idx = i32(a ^ info['X_INDEX_MAGIC'])
    return i32(arr[idx] ^ b ^ a)

CLASS_RE  = re.compile(r'^\s*(?:public|private|protected|static|final|abstract|\s)*(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)')
METHOD_RE = re.compile(r'^\s*(?:public|private|protected|static|final|synchronized|abstract|native|\s)*(?:<[^>]+>\s*)?'
                       r'[\w.$<>\[\],\s?&]+?\s+([a-zA-Z_$][\w$]*)\s*\([^)]*\)\s*(?:throws [\w.,\s]+)?\s*\{')
ANON_RE   = re.compile(r'new\s+[A-Za-z_$][\w$.<>,\s?&]*\s*\([^)]*\)\s*\{')

STATIC_RE = re.compile(r'^\s*static\s*\{$')
KEYWORDS = {'if','else','for','while','do','switch','case','default','try','catch','finally',
            'synchronized','return','throw','new','this','super','instanceof'}

def enclosing_map(text, outer):
    n = len(text); encl = [(outer, None)] * n
    stack = []      # (class_bin|None, method|None, depth_at_entry)
    depth = 0
    anon = {}
    def cur_class():
        for e in reversed(stack):
            if e[0] is not None: return e[0]
        return outer
    def cur_method():
        for e in reversed(stack):
            if e[1] is not None: return e[1]
        return None
    i = 0; ilc = ibc = istr = ich = False
    while i < n:
        c = text[i]; c2 = text[i:i+2]
        if ilc:
            if c == '\n': ilc = False
        elif ibc:
            if c2 == '*/': ibc = False; i += 1
        elif istr:
            if c == '\\': i += 1
            elif c == '"': istr = False
        elif ich:
            if c == '\\': i += 1
            elif c == "'": ich = False
        else:
            if c2 == '//': ilc = True; i += 1
            elif c2 == '/*': ibc = True; i += 1
            elif c == '"': istr = True
            elif c == "'": ich = True
            elif c == '{':
                ls = text.rfind('\n', 0, i) + 1
                line = text[ls:i+1].rstrip()
                mc = CLASS_RE.match(line); mm = METHOD_RE.match(line); ma = ANON_RE.search(line)
                pushed = False
                if mc:
                    nm = mc.group(1)
                    inner = nm if not stack else (cur_class() + '$' + nm)
                    stack.append((inner, None, depth)); anon.setdefault(inner, 0); pushed = True
                elif ma and not mc:
                    cc = cur_class()
                    anon[cc] = anon.get(cc, 0) + 1
                    stack.append((cc + '$' + str(anon[cc]), None, depth)); pushed = True
                elif STATIC_RE.match(line):
                    stack.append((None, '<clinit>', depth)); pushed = True
                elif mm and mm.group(1) not in KEYWORDS:
                    stack.append((None, mm.group(1), depth)); pushed = True
                if not pushed:
                    stack.append((None, None, depth))
                depth += 1
            elif c == '}':
                depth -= 1
                while stack and stack[-1][2] >= depth: stack.pop()
        encl[i] = (cur_class(), cur_method())
        i += 1
    return encl

def javastr(s):
    o = ['"']
    for ch in s:
        c = ord(ch)
        if   ch == '"':  o.append('\\"')
        elif ch == '\\': o.append('\\\\')
        elif ch == '\n': o.append('\\n')
        elif ch == '\r': o.append('\\r')
        elif ch == '\t': o.append('\\t')
        elif 0x20 <= c < 0x7f: o.append(ch)
        else: o.append(f'\\u{c:04x}')
    o.append('"'); return ''.join(o)

fail = []; totals = {'K2':0, 'K3':0, 'X':0}
for f in sorted(SRC.glob('*.java')):
    t0 = time.time()
    src = f.read_text()
    outer = f.stem
    methods = parse_methods(src)
    if not methods:
        (DST / f.name).write_text(src); print(f'  {f.name:26s} 0 methods (copied)'); continue
    encl = enclosing_map(src, outer)
    for m in methods:
        m['owner'] = encl[m['pos']][0] or outer
    method_by_owner = {}
    for m in methods:
        method_by_owner.setdefault(m['owner'], {})[m['name']] = m
    names = sorted({m['name'] for m in methods}, key=len, reverse=True)
    call_re = re.compile(
        r'\b(' + '|'.join(re.escape(n) for n in names) + r')\('
        r"(-?\d+),\s*(-?\d+)(?:,\s*'((?:\\u[0-9a-fA-F]{4}|\\.|.))')?"
        r'\)'
    )
    parts_out = []; last = 0
    for mm in call_re.finditer(src):
        parts_out.append(src[last:mm.start()])
        name = mm.group(1); a = int(mm.group(2)); b = int(mm.group(3)); ch_str = mm.group(4)
        cls_bin_here, meth_name = encl[mm.start()]
        parts_h = cls_bin_here.split('$')
        info = None
        for k in range(len(parts_h), 0, -1):
            cand = '$'.join(parts_h[:k])
            if cand in method_by_owner and name in method_by_owner[cand]:
                info = method_by_owner[cand][name]; break
        if info is None:
            fail.append((f.name, mm.start(), f'no method def {name}', mm.group(0)))
            parts_out.append(mm.group(0)); last = mm.end(); continue
        cls_fqn = f'com.xc17edb19a.{cls_bin_here}'
        # Find defining class in TABLES (has the table field)
        defining = None
        for k in range(len(parts_h), 0, -1):
            cand = f"com.xc17edb19a.{'$'.join(parts_h[:k])}"
            if cand in TABLES:
                t = TABLES[cand]
                which = t.get('strings' if info['kind'] != 'X' else 'ints', {})
                if info.get('table_field') and info['table_field'] in which:
                    defining = cand; break
        if defining is None:
            for cand, t in TABLES.items():
                which = t.get('strings' if info['kind'] != 'X' else 'ints', {})
                if info.get('table_field') and info['table_field'] in which:
                    defining = cand; break
        if defining is None:
            fail.append((f.name, mm.start(), 'no table', mm.group(0)))
            parts_out.append(mm.group(0)); last = mm.end(); continue
        tt = TABLES[defining]
        try:
            if info['kind'] == 'X':
                arr = tt['ints'][info['table_field']]
                parts_out.append(str(dec_X(arr, info, a, b))); totals['X'] += 1
            elif info['kind'] == 'K2':
                if meth_name is None: raise ValueError('no method')
                arr = tt['strings'][info['table_field']]
                parts_out.append(javastr(dec_K2(arr, info, a, b, cls_fqn, meth_name))); totals['K2'] += 1
            elif info['kind'] == 'K3':
                if meth_name is None: raise ValueError('no method')
                if ch_str is None: raise ValueError('no char')
                arr = tt['strings'][info['table_field']]
                parts_out.append(javastr(dec_K3(arr, info, a, b, parse_char_lit(ch_str), cls_fqn, meth_name))); totals['K3'] += 1
        except Exception as e:
            fail.append((f.name, mm.start(), str(e), mm.group(0)))
            parts_out.append(mm.group(0))
        last = mm.end()
    parts_out.append(src[last:])
    (DST / f.name).write_text(''.join(parts_out))
    print(f'  {f.name:26s} methods={len(methods)} took={time.time()-t0:.2f}s')

print(f"\ntotals: K2={totals['K2']} K3={totals['K3']} X={totals['X']}  failed={len(fail)}")
for r in fail[:10]: print(' ', r)
