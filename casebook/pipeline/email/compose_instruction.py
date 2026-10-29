#!/usr/bin/env python3
"""Compose a quote instruction email from a priced quote record (one call).

In:  a priced quote JSON (see SCHEMA below / example_quote.json).
Out: plain-text body + Outlook-style HTML body (+ warnings, + a round-trip check through
     casebook/quote_check/check_quote.py's instruction parser).

The signature is NOT added here. The text ends with the marker line [[SIGNATURE]] and the HTML
with <!--SIGNATURE-->; the send step (signature skill) drops the marker, puts the HTML into
{{BODY}} of email-signature/signature.html and appends "Kind Regards" + disclaimers to the text.

Usage:
  python3 compose_instruction.py quote.json [--out-dir DIR] [--stem NAME] [--print]
  exit 0 = composed and the parser reads back exactly the input, 1 = round-trip mismatch or
  missing required field, 2 = composed with warnings only.

  from compose_instruction import compose; r = compose(record)  # r['text'], r['html'], r['warnings']

SCHEMA (amounts are numbers in rand; a string is used verbatim, 'N/A' allowed for benefits):
  product            "corporate" | "sme" (the wording the quote is ISSUED on)
  quoter, liaison    first names for "Hi {quoter}," and the @mentions
  verb               "quote" (default) | "re-quote" | "add"
  entity             insured name; named in the opening line unless name_entity is false
  turnover | turnover_text, turnover_qualifier ("combined"), main_industry, sub_industry
  rm_text            default "without the RM fee"
  options            [{limit, premium, bi, bi_wait, cbi, cbi_wait, multimedia, regulatory,
                       third_party, emergency, system_damage, extortion, pci, computer_crime,
                       fp_auth, fp_unauth (corporate) | fp (SME), excess, cbi_requested}]
                     Missing benefits default to the limit; CBI defaults to 50% of BI; corporate FP
                     defaults to 10% authorised / 20% unauthorised; PCI and excess must be given.
  groups             optional group quote: [{label, header, turnover|turnover_text,
                       turnover_qualifier, main_industry, sub_industry, premiums: [[limit, prem]]}]
                     (benefit blocks still come from options; their premium is ignored)
  benefits_note      suffix after "Note the following benefits and endorsements" (e.g.
                     ", matched to the current policy")
  liaison_reason     after "...conditions of cover to the broker, " (default corporate reason)
  liaison_extra      free text after the reason
  mdr_fallback       {reason, premiums: [[limit, no-MDR premium]]}
  broker_questions   [str]; questions_intro overrides "Please also ask the broker to note and
                     confirm the following:"
  review             "send_back" (default) | "urgent" | "custom" (+ review_text)
  attachments        ["assessment form", "current schedule", ...]
  conditions         [str] in conditions_template.md wording; conditions_additional (bool),
                     within_30_days (default true)
  supersedes       true when this replaces an instruction already sent on the thread
  quoter_mention   name used in the @mention when it differs from the greeting name
  verb             also "additional" -> "Please quote the additional limits ..."
  options[].pending_reinsurer  adds "(pending Reinsurer approval as condition of cover)"
  also_sme         {premiums: [[limit, premium]], intro} SME fallback after the benefits block
  amount_style     "short" writes FP below R5M as R1M (older style); default R1,000,000
  labels           per-benefit label override, e.g. {"extortion": "Cyber Extortion"}
  cbi_na_wait_line false drops the CBI waiting-period line when CBI is N/A
"""
import argparse
import difflib
import html as _html
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASEBOOK = os.path.abspath(os.path.join(HERE, '..', '..'))
TEMPLATE = os.path.join(CASEBOOK, 'conditions_template.md')
CHECKER = os.path.join(CASEBOOK, 'quote_check', 'check_quote.py')
SIG_TEXT, SIG_HTML = '[[SIGNATURE]]', '<!--SIGNATURE-->'
DASH, APOS = '\u2013', '\u2019'

P = '<p class="MsoNormal" style="margin:0;font-family:Calibri,sans-serif;font-size:11pt">{}</p>'
UL = '<ul style="margin-top:0;margin-bottom:0">'
LI = '<li style="margin:0;font-family:Calibri,sans-serif;font-size:11pt;color:#000000">'

VERBS = {'quote': 'Please quote', 're-quote': 'Please re-quote', 'requote': 'Please re-quote', 'add': 'Please add',
         'additional': 'Please quote'}
CORP_BENEFITS = [('multimedia', 'Multimedia Liability Claims'), ('regulatory', 'Regulatory Expenses and Penalties'),
                 ('third_party', 'Third Party Claims'), ('emergency', 'Emergency Response Costs'),
                 ('system_damage', 'System Damage'), ('extortion', 'Cyber Extortion Costs'),
                 ('pci', 'PCI Fines and Penalties')]
SME_BENEFITS = [(k, 'Data Restoration' if k == 'system_damage' else lab) for k, lab in CORP_BENEFITS]
# Nuance-approved variants that are not word-for-word template lines.
ALLOWED_CONDITIONS = [
    'A formal, proactive vulnerability management program is in place.',
    'A separate backup set is immutable or completely isolated from production.',
    'The controls and procedures filled out in the submitted assessment form are at a minimum the level of all listed entities.',
    'Sophos MDR Complete deployed on all access devices and entire network, with endpoints deployed, or comparative Managed, Detection and Response program in place; if so, please specify.',
    'Data backups are done at least weekly.',
]

_cq = None


def checker():
    global _cq
    if _cq is None:
        spec = importlib.util.spec_from_file_location('check_quote', CHECKER)
        _cq = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_cq)
    return _cq


# ---------------------------------------------------------------- amounts
def is_na(v):
    return isinstance(v, str) and v.strip().upper() in ('N/A', 'NA', 'NONE', '')


def _round_to(v, step):
    return abs(v / step - round(v / step)) < 1e-6


def full(v):
    v = float(v)
    return f"R{v:,.2f}" if not _round_to(v, 1) else f"R{v:,.0f}"


def mill(v):
    return f"R{float(v) / 1e6:g}M"


def amt(v, style):
    """style: 'limit' -> R5M / R2.5M (full digits below R1M); 'fp' -> full digits below R5M
    (R500,000 / R1,000,000), else R5M; 'full' -> R250,000."""
    if v is None:
        return None
    if isinstance(v, str):
        return 'N/A' if is_na(v) else v.strip()
    v = float(v)
    if style == 'limit' and v >= 1e6 and _round_to(v, 1e5):
        return mill(v)
    if style == 'fp' and v >= 5e6 and _round_to(v, 1e5):
        return mill(v)
    return full(v)


def prem(v):
    return v.strip() if isinstance(v, str) else f"R{float(v):,.2f}"


def turnover_str(x):
    if x.get('turnover_text'):
        return x['turnover_text'].strip()
    v = x.get('turnover')
    if v is None:
        return None
    v = float(v)
    return mill(v) if v >= 1e6 and _round_to(v, 1e5) else full(v)


def join_and(items):
    items = [i for i in items if i]
    return items[0] if len(items) == 1 else ', '.join(items[:-1]) + ' and ' + items[-1]


# ---------------------------------------------------------------- blocks
def basis(x, rm, warn, who='quote'):
    to = turnover_str(x)
    if not to:
        warn.append(f'ERROR: turnover missing ({who})')
        to = 'R? '
    qual = (x.get('turnover_qualifier') + ' ') if x.get('turnover_qualifier') else ''
    parts = [f"{to} {qual}T/O"]
    main, sub = x.get('main_industry'), x.get('sub_industry')
    if main and sub:
        parts.append(f"Main/Sub-Industry: {main} -> {sub}")
    elif main:
        parts.append(f"Industry: {main}")
        warn.append(f'sub-industry missing ({who}); the checker cannot read the industry')
    else:
        warn.append(f'ERROR: industry missing ({who})')
    if rm:
        parts.append(rm)
    return ', '.join(parts)


def option_block(o, product, warn, fps='fp', na_wait=True, labels=None):
    labels = labels or {}
    """Returns (items, expected) where items = [(text, [child texts])] and expected is what the
    instruction parser should read back for this limit."""
    lim = float(o['limit'])
    tag = mill(lim)
    get = o.get
    items, exp = [], {'benefits': {}, 'waiting': {}, 'excess': None}
    bi = get('bi', lim)
    biw = str(get('bi_wait') or '12h')
    kids = [f"The waiting period on Business Interruption Loss is {biw}."]
    exp['waiting']['bi'] = biw.lower()
    exp['benefits']['bi'] = amt(bi, 'limit')
    if product != 'sme':
        if 'cbi' in o:
            cbi = o['cbi']
            if not is_na(cbi) and not is_na(bi) and abs(float(cbi) - 0.5 * float(bi)) > 0.5 and not get('cbi_requested'):
                warn.append(f"{tag}: Contingent BI {amt(cbi, 'limit')} is not 50% of BI {amt(bi, 'limit')} "
                            "(policy wording); set cbi_requested if the client asked for it")
        else:
            cbi = 'N/A' if is_na(bi) else 0.5 * float(bi)
        cw = 'N/A' if is_na(cbi) else str(get('cbi_wait') or biw)
        if not is_na(cbi) and cw != biw:
            warn.append(f"{tag}: CBI waiting period {cw} differs from BI {biw} (same unless the client asks)")
        kids.append(f"Contingent Business Interruption Loss benefit is {amt(cbi, 'limit')}.")
        exp['benefits']['cbi'] = amt(cbi, 'limit')
        if na_wait or not is_na(cbi):
            kids.append(f"The waiting period on Contingent Business Interruption Loss is {cw}.")
            exp['waiting']['cbi'] = cw.lower()
    items.append((f"Business Interruption Loss benefit is {amt(bi, 'limit')}.", kids))
    for k, label in (SME_BENEFITS if product == 'sme' else CORP_BENEFITS):
        label = labels.get(k, label)
        if k == 'pci' and 'pci' not in o:
            warn.append(f"{tag}: PCI not stated, defaulted to the full limit (state an amount or N/A)")
        v = get(k, lim)
        items.append((f"{label} benefit is {amt(v, 'limit')}.", []))
        exp['benefits'][k] = amt(v, 'limit')
    if product == 'sme':
        fp = get('fp')
        if fp is None:
            warn.append(f"ERROR: {tag}: SME Funds Protect amount missing")
        fp_on = fp is not None and not is_na(fp)
    else:
        fa = get('fp_auth', 0.1 * lim)
        fu = get('fp_unauth', 'N/A' if is_na(fa) else 2 * float(fa))
        fp_on = not is_na(fa)
    cc = get('computer_crime')
    if cc is not None:
        if fp_on:
            warn.append(f"{tag}: Computer Crime dropped, Funds Protect is on the quote")
        else:
            items.append((f"Computer Crime benefit is {amt(cc, 'limit')}.", []))
            exp['benefits']['computer_crime'] = amt(cc, 'limit')
    if product == 'sme':
        items.append((f"Funds Protect benefit is {amt(fp, fps)}.", []))
        exp['benefits']['fp'] = amt(fp, fps)
    else:
        items.append((f"Funds Protect authorised benefit is {amt(fa, fps)}.", []))
        items.append((f"Funds Protect unauthorised benefit is {amt(fu, fps)}.", []))
        exp['benefits']['fp_auth'] = amt(fa, fps)
        exp['benefits']['fp_unauth'] = amt(fu, fps)
    ex = get('excess')
    if ex is None:
        warn.append(f"ERROR: {tag}: excess missing")
    else:
        items.append((f"The excess is {amt(ex, 'full')}.", []))
        exp['excess'] = amt(ex, 'full')
    return items, exp


# ---------------------------------------------------------------- conditions
def template_conditions(path=TEMPLATE):
    try:
        return [l[2:].strip() for l in open(path, encoding='utf-8') if l.startswith('- ')]
    except OSError:
        return []


def _norm(s):
    s = s.replace(APOS, "'").replace('\u2018', "'").replace('\u201c', '"').replace('\u201d', '"')
    return re.sub(r'\s+', ' ', s).strip().rstrip('.').lower()


def condition_core(c):
    """Strip a trailing bracketed note: 'X (please confirm ...).' -> 'X.'"""
    m = re.match(r'^(.*?)\s*\((?:please|as an existing|the form|if )[^()]*(?:\([^()]*\)[^()]*)*\)\s*\.?\s*$', c, re.I)
    return (m.group(1).rstrip('.') + '.') if m else c


def check_conditions(conds, warn, questions, has_mdr_fallback):
    tpl = template_conditions()
    known = [_norm(t) for t in tpl + ALLOWED_CONDITIONS]
    noted = 0
    for c in conds:
        core = condition_core(c)
        if core != c:
            noted += 1
        if tpl and _norm(core) not in known:
            best = max(tpl + ALLOWED_CONDITIONS, key=lambda t: difflib.SequenceMatcher(None, _norm(t), _norm(core)).ratio())
            warn.append(f'condition not in template wording: "{core}" (closest: "{best}")')
        if 'cyber threat intelligence' in c.lower():
            warn.append('cyber threat intelligence condition: nuances say not to impose it while the scanner provides TI')
    if noted and not questions:
        warn.append(f'{noted} condition(s) carry a note but there are no broker questions; repeat the notes in the liaison paragraph')
    mdr = any(re.search(r'Sophos MDR|Managed, Detection and Response', c) for c in conds)
    if mdr and not has_mdr_fallback:
        warn.append('MDR condition on the quote but no no-MDR fallback rate given')
    if has_mdr_fallback and not mdr:
        warn.append('no-MDR fallback given but no MDR condition on the quote')


# ---------------------------------------------------------------- compose
def compose(q):
    warn = []
    product = (q.get('product') or 'corporate').lower()
    if product not in ('corporate', 'sme'):
        warn.append(f'ERROR: product {product!r} must be corporate or sme')
    quoter, liaison = q.get('quoter') or '{quoter}', q.get('liaison') or '{liaison}'
    qm = q.get('quoter_mention') or quoter
    prodname = 'SME' if product == 'sme' else 'corporate'
    rm = q.get('rm_text', 'without the RM fee')
    verb = VERBS.get((q.get('verb') or 'quote').lower(), 'Please quote')
    what = 'the additional limits' if (q.get('verb') or '').lower() == 'additional' else 'the following'
    opts = q.get('options') or []
    groups = q.get('groups') or []
    if not opts:
        warn.append('ERROR: no options')
    paras = [('p', f"Hi {quoter},")]
    if q.get('supersedes'):
        paras.append(('p', "Please ignore my previous e-mail on this thread, as this instruction replaces it."))

    expected = {'limits': {}, 'options': {}}
    if groups:
        paras.append(('p', f"{verb} the following group options on our {prodname} product ({rm}):"))
        for g in groups:
            paras.append(('p', f"Option ({g['label']}): {g['header']} ({basis(g, None, warn, 'option ' + g['label'])}):"))
            paras.append(('ul', [(f"{mill(l)} Cover @ {prem(p)} p/a.", []) for l, p in g['premiums']]))
            expected['options'][g['label'].lower()] = {float(l): float(p) for l, p in g['premiums']}
        n_prices = sum(len(g['premiums']) for g in groups)
    else:
        ent = f" for {q['entity']}" if q.get('entity') and q.get('name_entity', True) else ''
        paras.append(('p', f"{verb} {what} on our {prodname} product{ent} ({basis(q, rm, warn)}):"))
        lines = []
        for o in opts:
            if o.get('premium') is None:
                warn.append(f"ERROR: {mill(o['limit'])}: premium missing")
                continue
            lines.append((f"{mill(o['limit'])} Cover @ {prem(o['premium'])} p/a."
                          + (' (pending Reinsurer approval as condition of cover)' if o.get('pending_reinsurer') else ''), []))
        paras.append(('ul', lines))
        n_prices = len(opts)
    seen = set()
    paras.append(('p', "Note the following benefits and endorsements" + (q.get('benefits_note') or '') + ":"))
    for o in opts:
        lim = float(o['limit'])
        if lim in seen:
            warn.append(f"ERROR: limit {mill(lim)} appears twice")
        seen.add(lim)
        items, exp = option_block(o, product, warn, 'limit' if q.get('amount_style') == 'short' else 'fp',
                                  q.get('cbi_na_wait_line', True), q.get('labels'))
        exp['premium'] = None if groups else (float(o['premium']) if o.get('premium') is not None else None)
        expected['limits'][lim] = exp
        paras.append(('p', f"{mill(lim)} Cover" + (' (pending reinsurer approval as additional condition of cover)'
                                                    if o.get('pending_reinsurer') else '') + ':'))
        paras.append(('ul', items))

    # optional SME fallback option (lower-case 'cover' so the corporate checker does not read it as a limit)
    sme = q.get('also_sme')
    if sme and sme.get('premiums'):
        prs = sme['premiums']
        lead = f"a {mill(prs[0][0])} option" if len(prs) == 1 else 'the following options'
        paras.append(('p', sme.get('intro') or f"Also quote {lead} on the SME product, should the client not want "
                      "to move over to the corporate policy:"))
        paras.append(('ul', [(f"{mill(l)} cover @ {prem(p)} p/a.", []) for l, p in prs]))

    # liaison paragraph
    reason = q.get('liaison_reason')
    if reason is None:
        reason = 'since this is quoted on our corporate product' if product == 'corporate' else ''
    s = f"@{liaison} {DASH} please remember the endorsements and conditions of cover to the broker" + \
        (f", {reason}" if reason else '') + "."
    if q.get('liaison_extra'):
        s += ' ' + q['liaison_extra'].strip()
    mdr = q.get('mdr_fallback')
    if mdr:
        r = (mdr.get('reason') or '').strip().rstrip(',.')
        s += ' ' + (f"{r}, so we are trying the Sophos MDR route first." if r else "We are trying the Sophos MDR route first.")
        prs = mdr.get('premiums') or []
        rmb = f" ({rm})" if rm else ''
        if len(prs) == 1:
            s += f" If the client pushes back on it, the rate without the MDR condition is {prem(prs[0][1])} p/a{rmb}, with all other terms the same."
        elif prs:
            s += " If the client pushes back on it, the rates without the MDR condition are " + \
                 join_and([f"{prem(p)} p/a on {mill(l)}" for l, p in prs]) + f"{rmb}, with all other terms the same."
    qs = q.get('broker_questions') or []
    if qs:
        s += ' ' + (q.get('questions_intro') or 'Please also ask the broker to note and confirm the following:')
    paras.append(('p', s))
    if qs:
        paras.append(('ul', [(x, []) for x in qs]))

    # quoting-team paragraph
    rv = (q.get('review') or 'send_back').lower()
    if rv == 'urgent':
        s = f"@{qm} {DASH} This one is urgent, so please send it straight to the broker after you{APOS}ve reviewed it yourself."
    elif rv == 'custom' and q.get('review_text'):
        s = f"@{qm} {DASH} {q['review_text'].strip()}"
    else:
        s = f"@{qm} {DASH} Please send it back to me, after you{APOS}ve reviewed it yourself."
    att = q.get('attachments') or []
    if att:
        s += f" The {join_and(att)} {'is' if len(att) == 1 else 'are'} attached for the record on the admin system."
    paras.append(('p', s))

    conds = q.get('conditions') or []
    check_conditions(conds, warn, qs, bool(mdr))
    if conds:
        s = "Lastly, the above " + ('rates are' if n_prices > 1 else 'rate is') + \
            " under the assumption that the following " + ('additional ' if q.get('conditions_additional') else '') + \
            ('conditions of cover are' if len(conds) > 1 else 'condition of cover is') + " in place" + \
            (" (or implemented within 30 days of inception)" if q.get('within_30_days', True) else '') + ":"
        paras.append(('p', s))
        paras.append(('ul', [(c, []) for c in conds]))
    expected['conditions'] = conds

    text = render_text(paras)
    if product == 'corporate' and fp_any(opts) and re.search(r'computer crime', text, re.I):
        warn.append('ERROR: Computer Crime mentioned while Funds Protect is on')
    meta = {'product': product, 'n_options': n_prices, 'urgent': rv == 'urgent',
            'recipients_note': ('copy everyone who received the superseded instruction' if q.get('supersedes') else None),
            'attachments_to_save_from_request': att}
    rt = roundtrip(text, q, expected, groups)
    return {'text': text, 'html': render_html(paras), 'warnings': warn, 'roundtrip': rt, 'meta': meta}


def fp_any(opts):
    return any(not is_na(o.get('fp_auth', 1)) for o in opts)


# ---------------------------------------------------------------- render
def render_text(paras):
    out = []
    for kind, val in paras:
        if kind == 'p':
            out.append(val)
        else:
            lines = []
            for t, kids in val:
                lines.append('- ' + t)
                lines += ['    - ' + k for k in kids]
            out.append('\n'.join(lines))
    return '\n\n'.join(out) + '\n\n' + SIG_TEXT + '\n'


def _e(s):
    return _html.escape(s, quote=False)


def _ul(items):
    h = UL
    for t, kids in items:
        h += LI + _e(t)
        if kids:
            h += UL + ''.join(LI + _e(k) + '</li>' for k in kids) + '</ul>'
        h += '</li>'
    return h + '</ul>'


def render_html(paras):
    blank = P.format('&nbsp;')
    out = []
    for kind, val in paras:
        out.append(P.format(_e(val)) if kind == 'p' else _ul(val))
        out.append(blank)
    out.append(SIG_HTML)
    return '\n'.join(out)


# ---------------------------------------------------------------- round trip through the checker's parser
def roundtrip(text, q, expected, groups):
    cq = checker()
    ins = cq.parse_instruction(text)
    bad = []

    def m(s):
        return cq.money(s) if isinstance(s, str) else s

    if ins.get('product') != (q.get('product') or 'corporate').lower():
        bad.append(f"product read as {ins.get('product')}")
    if not groups:
        to = turnover_str(q)
        if to and ins.get('turnover') is not None and abs(ins['turnover'] - cq.money(to)) > 0.5:
            bad.append(f"turnover read as {ins.get('turnover')}")
        if q.get('main_industry') and q.get('sub_industry') and \
                (ins.get('main_industry'), ins.get('sub_industry')) != (q['main_industry'], q['sub_industry']):
            bad.append(f"industry read as {ins.get('main_industry')} -> {ins.get('sub_industry')}")
        if q.get('entity') and q.get('name_entity', True) and ins.get('entity') != q['entity']:
            bad.append(f"entity read as {ins.get('entity')}")
    for lab, prs in expected['options'].items():
        got = (ins.get('options') or {}).get(lab, {}).get('premiums', {})
        if {k: round(v, 2) for k, v in got.items()} != {k: round(v, 2) for k, v in prs.items()}:
            bad.append(f"option ({lab}) premiums read as {got}")
    if set(ins['limits']) != set(expected['limits']):
        bad.append(f"limits read as {sorted(ins['limits'])}, expected {sorted(expected['limits'])}")
    for lim, exp in expected['limits'].items():
        blk = ins['limits'].get(lim)
        if not blk:
            continue
        got_p = blk[next(iter(blk))]
        if exp['premium'] is not None and (got_p is None or abs(got_p - exp['premium']) > 0.005):
            bad.append(f"{mill(lim)} premium read as {got_p}")
        want = {k: m(v) for k, v in exp['benefits'].items()}
        if blk['benefits'] != want:
            diff = {k: (want.get(k), blk['benefits'].get(k)) for k in set(want) | set(blk['benefits'])
                    if want.get(k) != blk['benefits'].get(k)}
            bad.append(f"{mill(lim)} benefits differ (expected, read): {diff}")
        if blk['waiting'] != exp['waiting']:
            bad.append(f"{mill(lim)} waiting read as {blk['waiting']}")
        if exp['excess'] is not None and blk['excess'] != m(exp['excess']):
            bad.append(f"{mill(lim)} excess read as {blk['excess']}")
    if ins['conditions'] != expected['conditions']:
        bad.append(f"conditions read back {len(ins['conditions'])} of {len(expected['conditions'])} or changed")
    return {'ok': not bad, 'problems': bad}


# ---------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('quote_json')
    ap.add_argument('--out-dir', default=None)
    ap.add_argument('--stem', default=None)
    ap.add_argument('--print', action='store_true', help='print the plain-text body')
    a = ap.parse_args()
    q = json.load(open(a.quote_json, encoding='utf-8'))
    r = compose(q)
    out = a.out_dir or os.path.dirname(os.path.abspath(a.quote_json))
    stem = a.stem or re.sub(r'\.json$', '', os.path.basename(a.quote_json))
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, stem + '.instruction.txt'), 'w', encoding='utf-8').write(r['text'])
    open(os.path.join(out, stem + '.instruction.html'), 'w', encoding='utf-8').write(r['html'])
    json.dump({'warnings': r['warnings'], 'roundtrip': r['roundtrip'], 'meta': r['meta']},
              open(os.path.join(out, stem + '.compose.json'), 'w', encoding='utf-8'), indent=1)
    if a.print:
        print(r['text'])
    errs = [w for w in r['warnings'] if w.startswith('ERROR')]
    for w in r['warnings']:
        print('WARN ' + w, file=sys.stderr)
    for p in r['roundtrip']['problems']:
        print('ROUNDTRIP ' + p, file=sys.stderr)
    print(f"composed {stem}: {len(r['warnings'])} warnings, round-trip {'ok' if r['roundtrip']['ok'] else 'FAILED'}",
          file=sys.stderr)
    sys.exit(1 if errs or not r['roundtrip']['ok'] else 2 if r['warnings'] else 0)


if __name__ == '__main__':
    main()
