#!/usr/bin/env python3
"""Returned-quote check.

Compares a quote issued by the admin platform (PDF today, ERP JSON later)
against the quote instruction that was SENT, field by field, and optionally
checks the broker cover email against the issued quote.

Design: two adapters produce one normalised shape, and the comparator only
sees that shape. A future ERP adds `quote_from_erp_json()` and nothing else
changes.

  instruction (email text)  -> parse_instruction() -> {"limits": {limit: {...}}, ...}
  quote (PDF / text / ERP)  -> parse_quote_text()  -> {"items": [{...}], ...}
  compare(instruction, quote) -> rows of (field, expected, found, status)

Usage:
  python3 check_quote.py --instruction sent.txt [--section b1_01] --quote quote.pdf [--quote q2.pdf]
                         [--entity "Name (Pty) Ltd"] [--cover-email cover.txt] [--json out.json]
Exit code 0 = all match, 1 = at least one MISMATCH, 2 = only CHECK items.
"""
import argparse, difflib, json, re, sys

RM_RATE = 0.06  # Risk Mitigation Fee, 6% of premium, added on top when the instruction says "without RM fee"
BULLET = re.compile(r'^[\s\*\-\u2022\u25aa\u00b7o]+\s+')


# ---------------------------------------------------------------- helpers
def money(s):
    """'R50M' 'R2.5M' 'R500,000' 'R1,14B' 'R50 000 000.00' -> float; 'N/A' -> 'N/A'; else None."""
    if s is None:
        return None
    s = s.strip().replace('\u00a0', ' ')
    if re.match(r'^n/?a\b', s, re.I):
        return 'N/A'
    m = re.search(r'R\s*(\d(?:[\d,\.]|\s(?=\d))*)\s*([KkMmBb])?(?![A-Za-z])', s)
    if not m:
        return None
    num, unit = m.group(1).strip().rstrip('.'), (m.group(2) or '').upper()
    if unit:
        num = num.replace(' ', '')
        if ',' in num and '.' not in num and len(num.split(',')[-1]) != 3:
            num = num.replace(',', '.')          # R1,14B = 1.14 billion
        return float(num.replace(',', '')) * {'K': 1e3, 'M': 1e6, 'B': 1e9}[unit]
    return float(num.replace(' ', '').replace(',', ''))


def fmt(v):
    if v is None:
        return '-'
    if isinstance(v, float):
        return f"R{v:,.2f}" if v % 1 else f"R{v:,.0f}"
    return str(v)


def norm(s):
    return re.sub(r'\s+', ' ', re.sub(r'[^a-z0-9%/ ]', ' ', (s or '').lower())).strip()


def bkey(name):
    n = name.lower()
    if 'contingent' in n:
        return 'cbi'
    if 'business interruption' in n:
        return 'bi'
    if 'funds protect' in n:
        if 'unauth' in n:
            return 'fp_unauth'
        if 'auth' in n:
            return 'fp_auth'
        return 'fp'
    for w, k in (('multimedia', 'multimedia'), ('regulatory', 'regulatory'), ('third party', 'third_party'),
                 ('emergency', 'emergency'), ('pci', 'pci'), ('computer crime', 'computer_crime'),
                 ('data restoration', 'system_damage'), ('system', 'system_damage')):
        if w in n:
            return k
    if n.startswith('cyber') and 'protect' not in n:
        return 'extortion'
    return re.sub(r'\W+', '_', n).strip('_')


BENEFIT_LABEL = {'bi': 'Business Interruption', 'cbi': 'Contingent BI', 'multimedia': 'Multimedia Liability',
                 'regulatory': 'Regulatory Expenses', 'third_party': 'Third Party Claims',
                 'emergency': 'Emergency Response', 'system_damage': 'System Damage / Data Restoration',
                 'extortion': 'Cyber Extortion', 'pci': 'PCI Fines and Penalties', 'fp': 'Funds Protect',
                 'fp_auth': 'Funds Protect authorised', 'fp_unauth': 'Funds Protect unauthorised'}


# ---------------------------------------------------------------- instruction adapter
def load_instruction_text(path, section=None):
    t = open(path, encoding='utf-8', errors='replace').read()
    if section:
        parts = re.split(r'^===== (\S+).*$', t, flags=re.M)
        t = '\n'.join(parts[i + 1] for i in range(1, len(parts), 2) if parts[i].startswith(section))
    return t


def parse_instruction(text):
    lines = [l.rstrip() for l in text.splitlines()]
    flat = ' '.join(l.strip() for l in lines)
    ins = {'limits': {}, 'conditions': [], 'notes': []}
    m = re.search(r'(R[\d\.,]+\s*[MBK]?)\s*T/O', flat, re.I)
    ins['turnover_text'] = m.group(1) if m else None
    ins['turnover'] = money(m.group(1)) if m else None
    ins['turnover_rounded'] = bool(m and re.search(r'[MBK]\s*$', m.group(1).strip(), re.I))
    m = re.search(r'Main/Sub-Industry:?\s*(.+?)\s*(?:->|–>|→|-)>?\s*(.+?)(?=,\s*(?:without|including|excluding|with)\b|\)|$)', flat)
    ins['main_industry'], ins['sub_industry'] = (m.group(1).strip(), m.group(2).strip()) if m else (None, None)
    m = re.search(r'\bfor (.+?) \(R\d', flat)
    ins['entity'] = m.group(1).strip() if m else None
    m = re.search(r'on our (corporate|SME|business) product', flat, re.I)
    ins['product'] = m.group(1).lower() if m else None
    if re.search(r'no RM\b', flat, re.I):
        ins['rm'] = 'none'
    elif re.search(r'without (the )?RM( fee)?', flat, re.I):
        ins['rm'] = 'added'
    else:
        ins['rm'] = 'unknown'
    m = re.search(r'without (?:the )?RM fee ([^,\)]*except[^,\)]*)', flat, re.I)
    if m:
        ins['notes'].append('RM exception in instruction: "' + m.group(1).strip() + '"')

    # premiums per limit (group instructions may carry several options with the same limits)
    ins['options'] = {}
    opt = None
    for l in lines:
        o = re.match(r'^Option \((\w+)\):\s*(.*)$', BULLET.sub('', l).strip(), re.I)
        if o:
            opt = o.group(1).lower()
            hdr = o.group(2).strip()
            t = re.search(r'(R[\d\.,]+\s*[MBK]?)\s*(?:combined\s+)?T/O', hdr, re.I)
            ins['options'][opt] = {'header': hdr, 'premiums': {},
                                   'turnover_text': t.group(1) if t else None,
                                   'turnover': money(t.group(1)) if t else None,
                                   'turnover_rounded': bool(t and re.search(r'[MBK]\s*$', t.group(1).strip(), re.I))}
            continue
        if re.match(r'^\s*Note the following', l, re.I):
            opt = None
        m = re.search(r'R([\d\.,]+\s*[MB])\s*Cover\s*@\s*(R[\d,\.]+)', l)
        if m and opt:
            ins['options'][opt]['premiums'][money('R' + m.group(1))] = money(m.group(2))
        if m:
            lim = money('R' + m.group(1))
            ins['limits'][lim] = {'premium': money(m.group(2)), 'benefits': {}, 'waiting': {}, 'excess': None,
                                  'pending_reinsurer': bool(re.search(r'reinsurer', l, re.I)),
                                  'line': BULLET.sub('', l).strip()}
    # benefit blocks
    cur = None
    for l in lines:
        s = BULLET.sub('', l).strip()
        h = re.match(r'^R([\d\.,]+\s*[MB])\s+Cover(?:\s*\(([^)]*)\))?\s*:\s*$', s, re.I)
        if h:
            cur = money('R' + h.group(1))
            ins['limits'].setdefault(cur, {'premium': None, 'benefits': {}, 'waiting': {}, 'excess': None,
                                           'pending_reinsurer': False, 'line': ''})
            if h.group(2) and 'reinsurer' in h.group(2).lower():
                ins['limits'][cur]['pending_reinsurer'] = True
            continue
        if s.startswith('@') or s.lower().startswith('lastly'):
            cur = None
        if cur is None:
            continue
        blk = ins['limits'][cur]
        w = re.match(r'^The waiting period on (Contingent )?Business Interruption Loss is (\S+?)\.?$', s, re.I)
        if w:
            blk['waiting']['cbi' if w.group(1) else 'bi'] = w.group(2).lower()
            continue
        e = re.match(r'^The excess is (.+?)\.?$', s, re.I)
        if e:
            blk['excess'] = money(e.group(1))
            continue
        b = re.match(r'^(.+?) benefit is (.+?)\.?$', s, re.I)
        if b:
            blk['benefits'][bkey(b.group(1))] = money(b.group(2))
    # conditions
    start = None
    for i, l in enumerate(lines):
        if re.search(r'conditions? of cover (are|is) in place', l, re.I):
            start = i + 1
            break
    if start is not None:
        seen = False
        for l in lines[start:]:
            if BULLET.match(l):
                ins['conditions'].append(BULLET.sub('', l).strip())
                seen = True
            elif l.strip() and seen:
                break
    return ins


# ---------------------------------------------------------------- quote adapters
def quote_text_from_file(path):
    if path.lower().endswith('.pdf'):
        import pymupdf
        d = pymupdf.open(path)
        return '\n'.join(p.get_text() for p in d)
    return open(path, encoding='utf-8', errors='replace').read()


def _after(lines, label, start=0, stop=None):
    for i in range(start, stop or len(lines)):
        if lines[i] == label and i + 1 < len(lines):
            return lines[i + 1]
    return None


def _money_after(lines, pattern, start=0):
    rx = re.compile(pattern)
    for i in range(start, len(lines) - 1):
        if rx.match(lines[i]):
            for j in range(i + 1, min(i + 4, len(lines))):
                v = money(lines[j])
                if isinstance(v, float):
                    return v
    return None


def parse_quote_text(text, source=''):
    L = [l.strip() for l in text.splitlines() if l.strip()]
    flat = ' '.join(L)
    q = {'source': source}
    m = re.search(r'Quote Number:?\s*(QT\d+)', flat)
    q['quote_no'] = m.group(1) if m else None
    q['company'] = _after(L, 'Company Name')
    q['contract_type'] = _after(L, 'Contract Type')
    q['cover_start'] = _after(L, 'Cover Start Date')
    m = re.search(r'(Cyber Protect (?:Corporate|Business) Policy)', flat)
    q['product'] = m.group(1) if m else None
    q['section_premium'] = _money_after(L, r'^Cover Sub-Total$')
    q['rm_fee'] = _money_after(L, r'^Risk Management Fee$')
    q['total_payment'] = _money_after(L, r'^Total (Annual|Monthly) Payment$')
    q['computer_crime_shown'] = 'computer crime' in flat.lower()
    q['fp_fraud_conditions'] = 'Conditions of Cover Funds Protect' in flat

    # endorsements and conditions
    e0 = next((i for i, l in enumerate(L) if l == 'Quote Endorsements'), None)
    c0 = next((i for i, l in enumerate(L) if re.match(r'The above rates? (?:is|are) under the assumption', l)), None)
    c1 = next((i for i, l in enumerate(L) if l.startswith('Conditions of Cover Funds Protect')
               or l.startswith('Valid from') or l == 'ITEMS ON COVER'), None) if c0 is not None else None
    endo = ' '.join(L[e0 + 1:(c0 if c0 is not None else e0 + 12)]) if e0 is not None else ''
    endo = endo.replace('Conditions of Cover:', ' ')
    q['endorsements_text'] = endo.strip()
    w = re.search(r'(?<!Contingent )Business Interruption Loss is (\S+?)\.', endo)
    wc = re.search(r'waiting period on Contingent Business Interruption Loss is (\S+?)\.', endo)
    cb = re.search(r'Contingent Business Interruption Loss benefit is (R[\d\.,]+\s*[MKB]?|N/A)', endo, re.I)
    q['waiting'] = {'bi': w.group(1).lower() if w else None, 'cbi': wc.group(1).lower() if wc else None}
    q['cbi_benefit'] = money(cb.group(1)) if cb else None
    conds = []
    if c0 is not None:
        for l in L[c0 + 1:c1]:
            if l.startswith('- '):
                conds.append(l[2:].strip())
            elif conds:
                conds[-1] += ' ' + l
    q['conditions'] = conds

    # items on cover (one or more limits)
    starts = [i for i, l in enumerate(L) if re.match(r'^Item \d+ - R', l)]
    items = []
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else next(
            (i for i in range(s, len(L)) if L[i].startswith('TOTAL SECTION') or L[i] == 'Selected Policy Level Benefits'), len(L))
        seg = L[s:e]
        it = {'limit': money(seg[0].split(' - ', 1)[1]), 'benefits': {}}
        it['premium'] = _money_after(seg, r'^Item [A-Za-z]+$')
        it['turnover'] = _money_after(seg, r'^Revenue / Turnover$')
        it['main_industry'] = _after(seg, 'Main Industry')
        si = next((i for i, l in enumerate(seg) if l == 'Sub Industry'), None)
        bi = next((i for i, l in enumerate(seg) if l == 'Benefits Sub Limits'), None)
        it['sub_industry'] = ' '.join(seg[si + 1:bi]) if si is not None and bi is not None else None
    if it['sub_industry']:
        # the quote layout puts the risk address and cover limit before 'Benefits Sub Limits'
        it['sub_industry'] = re.split(r'\s+(?:Risk Group Address|Risk Address|Address|Cover Limit)\b',
                                      it['sub_industry'])[0].strip()
        if bi is not None:
            i = bi + 1
            while i < len(seg) - 1:
                lab, val = seg[i], money(seg[i + 1])
                if lab == 'Excess':
                    it['excess'] = val if isinstance(val, float) else None
                    break
                if isinstance(val, float) or val == 'N/A':
                    it['benefits'][bkey(lab)] = val
                    i += 2
                else:
                    i += 1
        items.append(it)
    q['items'] = items
    return q


def quote_from_erp_json(obj):
    """Placeholder for the in-house ERP: map its quote record onto the same shape as parse_quote_text()."""
    raise NotImplementedError('Map the ERP quote record fields onto parse_quote_text() keys here.')


# ---------------------------------------------------------------- comparator
def compare(ins, q, entity=None):
    rows = []

    def add(field, exp, got, status, limit=None):
        rows.append({'limit': limit, 'field': field, 'instruction': exp, 'quote': got, 'status': status})

    def eqm(a, b, tol=0.01):
        return isinstance(a, float) and isinstance(b, float) and abs(a - b) <= tol

    ent = entity or ins.get('entity')
    if ent:
        st = 'MATCH' if norm(ent) == norm(q.get('company')) else 'MISMATCH'
        add('Insured entity name', ent, q.get('company'), st)
    else:
        add('Insured entity name', '(not named in instruction)', q.get('company'), 'CHECK')
    if ins.get('product'):
        ok = q.get('product') and ins['product'] in q['product'].lower() or (
            ins['product'] == 'sme' and q.get('product') and 'business' in q['product'].lower())
        add('Product', ins['product'], q.get('product'), 'MATCH' if ok else 'MISMATCH')
    add('Quote number', '-', q.get('quote_no'), 'INFO')
    add('Contract type', '-', q.get('contract_type'), 'INFO')

    if not q['items']:
        add('Items on cover', 'at least one', 'none read', 'MISMATCH')
    for it in q['items']:
        lim = it['limit']
        blk = ins['limits'].get(lim)
        if blk is None:
            add('Cover limit', 'one of ' + ', '.join(fmt(x) for x in ins['limits']), fmt(lim), 'MISMATCH', lim)
            continue
        add('Cover limit', fmt(lim), fmt(lim), 'MATCH', lim)
        add('Annual premium excl. RM', fmt(blk['premium']), fmt(it.get('premium')),
            'MATCH' if eqm(blk['premium'], it.get('premium')) else 'MISMATCH', lim)
        t_exp, t_got = ins.get('turnover'), it.get('turnover')
        if isinstance(t_exp, float) and isinstance(t_got, float):
            tol = 0.01 * t_exp if ins.get('turnover_rounded') else 1.0
            st = 'MATCH' if abs(t_exp - t_got) <= tol else 'MISMATCH'
        else:
            st = 'CHECK'
        add('Turnover', ins.get('turnover_text') or '-', fmt(t_got), st, lim)
        for f in ('main_industry', 'sub_industry'):
            a, b = ins.get(f), it.get(f)
            if not a:
                add(f.replace('_', ' ').capitalize(), '-', b, 'CHECK', lim)
                continue
            ab = lambda s: re.sub(r'\badmin\b', 'administration', norm(s))
            r = difflib.SequenceMatcher(None, ab(a), ab(b)).ratio()
            st = 'MATCH' if ab(a) == ab(b) else ('CHECK' if r >= 0.75 or norm(a) in norm(b) or norm(b) in norm(a) else 'MISMATCH')
            add(f.replace('_', ' ').capitalize(), a, b, st, lim)
        # benefits
        for k, v in blk['benefits'].items():
            if k == 'cbi':
                got = q.get('cbi_benefit')
                if v == 'N/A':
                    st = 'MATCH' if got in (None, 'N/A') else 'MISMATCH'
                else:
                    st = 'MATCH' if eqm(v, got) else 'MISMATCH'
                add('Contingent BI (endorsement)', fmt(v), fmt(got) if got is not None else 'not shown', st, lim)
                continue
            got = it['benefits'].get(k)
            if v == 'N/A':
                st = 'MATCH' if got in (None, 'N/A') else 'MISMATCH'
                add(BENEFIT_LABEL.get(k, k), 'N/A', fmt(got) if got is not None else 'not shown', st, lim)
            else:
                add(BENEFIT_LABEL.get(k, k), fmt(v), fmt(got) if got is not None else 'not shown',
                    'MATCH' if eqm(v, got) else 'MISMATCH', lim)
        for k in it['benefits']:
            if k not in blk['benefits'] and k != 'cbi':
                add(BENEFIT_LABEL.get(k, k), 'not instructed', fmt(it['benefits'][k]), 'CHECK', lim)
        for k, v in blk['waiting'].items():
            got = q['waiting'].get(k)
            na = str(v).lower() in ('n/a', 'na', 'none')
            add(('CBI' if k == 'cbi' else 'BI') + ' waiting period', v, got or 'not shown',
                'MATCH' if got == v or (na and got in (None, 'n/a', 'N/A')) else 'MISMATCH', lim)
        add('Excess', fmt(blk['excess']), fmt(it.get('excess')),
            'MATCH' if eqm(blk['excess'], it.get('excess')) else 'MISMATCH', lim)
        if blk.get('pending_reinsurer'):
            txt = (q.get('endorsements_text', '') + ' ' + ' '.join(q['conditions'])).lower()
            add('Pending reinsurer approval endorsement', 'required', 'shown' if 'reinsurer' in txt else 'not shown',
                'MATCH' if 'reinsurer' in txt else 'MISMATCH', lim)

    # quote-level checks
    fp_on = any(isinstance(b['benefits'].get(k), float) and b['benefits'].get(k) > 0
                for b in ins['limits'].values() for k in ('fp', 'fp_auth', 'fp_unauth'))
    if fp_on:
        add('Computer Crime not shown (Funds Protect on)', 'absent', 'shown' if q['computer_crime_shown'] else 'absent',
            'MISMATCH' if q['computer_crime_shown'] else 'MATCH')
        add('Funds Protect fraud-control conditions', 'present', 'present' if q['fp_fraud_conditions'] else 'absent',
            'MATCH' if q['fp_fraud_conditions'] else 'MISMATCH')
    prem, fee, tot = q.get('section_premium'), q.get('rm_fee'), q.get('total_payment')
    if ins['rm'] == 'added':
        exp = round(prem * RM_RATE, 2) if isinstance(prem, float) else None
        add('RM fee (6% on top)', fmt(exp), fmt(fee), 'MATCH' if eqm(exp, fee, 0.02) else 'MISMATCH')
        if isinstance(prem, float) and isinstance(fee, float):
            add('Total = premium + RM fee', fmt(prem + fee), fmt(tot), 'MATCH' if eqm(prem + fee, tot, 0.02) else 'MISMATCH')
    elif ins['rm'] == 'none':
        add('RM fee', 'none', fmt(fee), 'MATCH' if not fee else 'MISMATCH')
    for n in ins.get('notes', []):
        add('Instruction note', n, '-', 'CHECK')

    # conditions, word for word
    qn = {norm(c): c for c in q['conditions']}
    used = set()
    for c in ins['conditions']:
        n = norm(c)
        if n in qn:
            add('Condition', c, 'word for word', 'MATCH'); used.add(n); continue
        best = max(qn, key=lambda x: difflib.SequenceMatcher(None, n, x).ratio(), default=None)
        r = difflib.SequenceMatcher(None, n, best).ratio() if best else 0
        if best and r >= 0.85:
            add('Condition', c, qn[best], 'MISMATCH (wording)'); used.add(best)
        else:
            add('Condition', c, 'missing', 'MISMATCH')
    for n, c in qn.items():
        if n not in used:
            add('Condition', 'not instructed', c, 'MISMATCH (extra)')
    if not ins['conditions']:
        add('Conditions of cover', 'none read from instruction', f"{len(q['conditions'])} in quote", 'CHECK')
    return rows


def check_cover_email(text, quotes, ins):
    """Broker cover email: every amount it states must exist on the issued quote(s); limits and conditions referenced."""
    rows = []
    flat = ' '.join(text.split())
    known = set()
    for q in quotes:
        for v in (q.get('section_premium'), q.get('rm_fee'), q.get('total_payment')):
            if isinstance(v, float):
                known.add(round(v, 2)); known.add(round(v / 12, 2))
        for it in q['items']:
            known.update(round(x, 2) for x in [it.get('limit'), it.get('premium'), it.get('excess')] + list(it['benefits'].values())
                         if isinstance(x, float))
            if isinstance(q.get('cbi_benefit'), float):
                known.add(round(q['cbi_benefit'], 2))
    for m in re.finditer(r'R\s?\d[\d ,\.]*\s?[MBK]?(?![A-Za-z])', flat):
        v = money(m.group(0))
        if isinstance(v, float) and v >= 1000:
            ok = any(abs(v - k) <= 0.02 for k in known)
            rows.append({'limit': None, 'field': 'Cover email amount', 'instruction': '-', 'quote': m.group(0).strip(),
                         'status': 'MATCH' if ok else 'MISMATCH (not on quote)'})
    for q in quotes:
        for it in q['items']:
            lim = it['limit']
            lab = f"R{lim / 1e6:g}M"
            hit = lab.lower() in flat.lower() or fmt(lim) in flat
            rows.append({'limit': lim, 'field': 'Cover email mentions limit', 'instruction': lab, 'quote': '-',
                         'status': 'MATCH' if hit else 'CHECK'})
    cond_ref = bool(re.search(r'condition', flat, re.I))
    rows.append({'limit': None, 'field': 'Cover email refers to conditions of cover', 'instruction': 'yes',
                 'quote': 'yes' if cond_ref else 'no', 'status': 'MATCH' if cond_ref or not ins['conditions'] else 'MISMATCH'})
    if any(b.get('pending_reinsurer') for b in ins['limits'].values()):
        r = 'reinsurer' in flat.lower()
        rows.append({'limit': None, 'field': 'Cover email states pending reinsurer approval', 'instruction': 'yes',
                     'quote': 'yes' if r else 'no', 'status': 'MATCH' if r else 'MISMATCH'})
    return rows


def to_markdown(rows):
    out = ['| Limit | Item | Instruction | Quote | Result |', '|---|---|---|---|---|']
    for r in rows:
        out.append(f"| {fmt(r['limit']) if r['limit'] else ''} | {r['field']} | {r['instruction']} | {r['quote']} | {r['status']} |")
    return '\n'.join(out)


def apply_option(ins, label):
    """Point the limits at one option of a multi-option (group) instruction."""
    opts = ins.get('options') or {}
    if not opts:
        return
    if not label or label.lower() not in opts:
        ins['notes'].append('Instruction has options ' + ', '.join('(%s)' % k for k in opts)
                            + '; pass --option to check the premium and turnover of the right one')
        return
    o = opts[label.lower()]
    for lim in list(ins['limits']):
        if lim not in o['premiums']:
            del ins['limits'][lim]
    for lim, p in o['premiums'].items():
        first = next(iter(ins['limits'][lim]))
        ins['limits'][lim][first] = p
    if o.get('turnover') is not None:
        ins['turnover'], ins['turnover_text'], ins['turnover_rounded'] = o['turnover'], o['turnover_text'], o['turnover_rounded']
    ins['notes'].append('Checked against option (%s): %s' % (label.lower(), o['header']))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--instruction', required=True)
    ap.add_argument('--section')
    ap.add_argument('--quote', action='append', required=True)
    ap.add_argument('--entity')
    ap.add_argument('--cover-email')
    ap.add_argument('--json')
    ap.add_argument('--option', help='group instruction option label, e.g. a or b')
    a = ap.parse_args()
    ins = parse_instruction(load_instruction_text(a.instruction, a.section))
    apply_option(ins, a.option)
    quotes, rows = [], []
    for p in a.quote:
        q = parse_quote_text(quote_text_from_file(p), p)
        quotes.append(q)
        rows += [dict(r, quote_file=p) for r in compare(ins, q, a.entity)]
    missing = [l for l in ins['limits'] if not any(it['limit'] == l for q in quotes for it in q['items'])]
    for l in missing:
        rows.append({'limit': l, 'field': 'Instructed limit has a quote', 'instruction': 'yes', 'quote': 'no quote file', 'status': 'CHECK'})
    if a.cover_email:
        rows += check_cover_email(open(a.cover_email, encoding='utf-8', errors='replace').read(), quotes, ins)
    bad = [r for r in rows if r['status'].startswith('MISMATCH')]
    chk = [r for r in rows if r['status'] == 'CHECK']
    print(f"Result: {len(bad)} mismatch, {len(chk)} to check, {sum(r['status']=='MATCH' for r in rows)} match")
    print(to_markdown(rows))
    if a.json:
        json.dump({'instruction': ins, 'quotes': quotes, 'rows': rows}, open(a.json, 'w'), indent=1, default=str)
    sys.exit(1 if bad else 2 if chk else 0)


if __name__ == '__main__':
    main()
