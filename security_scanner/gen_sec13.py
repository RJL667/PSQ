import xml.sax.saxutils as saxutils

TABLE_W = 9360
col_widths = [2400, 2200, 3000, 1760]

BORDER = '<w:tcBorders><w:top w:val="single" w:sz="1" w:space="0" w:color="999999"/><w:left w:val="single" w:sz="1" w:space="0" w:color="999999"/><w:bottom w:val="single" w:sz="1" w:space="0" w:color="999999"/><w:right w:val="single" w:sz="1" w:space="0" w:color="999999"/></w:tcBorders>'
MARGIN = '<w:tcMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/><w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>'
HDR_FILL = '<w:shd w:val="clear" w:color="auto" w:fill="1B2A4A"/>'
YOUR_FILL = '<w:shd w:val="clear" w:color="auto" w:fill="FFF2CC"/>'

pid = [0x16D00001]
def np():
    pid[0] += 1
    return f'{pid[0]:08X}'

def hcell(text, w):
    t = saxutils.escape(text)
    return f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{BORDER}{HDR_FILL}{MARGIN}</w:tcPr><w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:r><w:rPr><w:b/><w:bCs/><w:color w:val="FFFFFF"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t>{t}</w:t></w:r></w:p></w:tc>'

def dcell(text, w, your_val=False):
    t = saxutils.escape(str(text))
    fill = YOUR_FILL if your_val else ''
    color = '<w:color w:val="CC0000"/>' if your_val else ''
    return f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/>{BORDER}{fill}{MARGIN}</w:tcPr><w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:r><w:rPr>{color}<w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">{t}</w:t></w:r></w:p></w:tc>'

def make_table(header_labels, rows_data):
    grid = ''.join(f'<w:gridCol w:w="{w}"/>' for w in col_widths)
    lines = [f'<w:tbl><w:tblPr><w:tblW w:w="{TABLE_W}" w:type="dxa"/><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:left w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:right w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="auto"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="auto"/></w:tblBorders><w:tblCellMar><w:left w:w="10" w:type="dxa"/><w:right w:w="10" w:type="dxa"/></w:tblCellMar><w:tblLook w:val="0000" w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" w:noHBand="0" w:noVBand="0"/></w:tblPr><w:tblGrid>{grid}</w:tblGrid>']
    hdr = ''.join(hcell(h, w) for h, w in zip(header_labels, col_widths))
    lines.append(f'<w:tr w:rsidR="00A108AD" w14:paraId="{np()}" w14:textId="77777777">{hdr}</w:tr>')
    for param, val, desc in rows_data:
        cells = dcell(param, col_widths[0]) + dcell(val, col_widths[1]) + dcell(desc, col_widths[2]) + dcell('', col_widths[3], your_val=True)
        lines.append(f'<w:tr w:rsidR="00A108AD" w14:paraId="{np()}" w14:textId="77777777">{cells}</w:tr>')
    lines.append('</w:tbl>')
    return '\n'.join(lines)

parts = []

parts.append(f'<w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>13. Regulatory Exposure (C2 Jurisdiction Model)</w:t></w:r></w:p>')

parts.append(f'<w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:pPr><w:spacing w:after="80"/></w:pPr><w:r><w:rPr><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr><w:t xml:space="preserve">Each jurisdiction is computed independently and summed into C2. This replaces the previous multiplier approach. POPIA is always applied (Section 109 administrative fines, statutory ceiling R10M). GDPR and PCI are toggled via scanner UI checkboxes. Fines from different regulators genuinely stack (POPIA fines for SA data protection, PCI for card data, GDPR for EU data). Civil liability under POPIA Section 99 and common-law delict is uncapped and excluded from this model; see Civil Liability Disclosure for the rationale.</w:t></w:r></w:p>')

rows = [
    ('POPIA (always applied)', 'min(R10M, rev x 2%)', 'SA Information Regulator, Section 109 (Administrative fines). Statutory ceiling R10M. The 2% turnover figure is an internal capacity-scaling heuristic for the Section 109(3) factors (nature, duration, extent, number of subjects, public importance, prevention, prior offences) and is NOT a statutory formula - POPIA does not specify a percentage trigger.'),
    ('POPIA Section 99 (civil)', 'Uncapped - excluded', 'Civil action by data subjects under Section 99. Damages can include patrimonial loss, non-patrimonial loss, and aggravated damages. Excluded from the financial impact figures - depends on contractual data invisible to an external scan. See Civil Liability Disclosure.'),
    ('GDPR (if EU data processed)', 'rev x 4% (uncapped)', 'EU third-party liability. Not directly enforceable against SA entities without EU presence, but EU data subjects can pursue claims.'),
    ('PCI DSS (if card data)', 'R1M x (1 - adj_compliance)', 'Card scheme fines. External scanner visibility capped at 30% of PCI requirements. Fine range R700K-R1M from external assessment alone.'),
    ('PCI external visibility cap', '30%', 'Scanner covers ~10 of ~250 PCI sub-requirements. Full assessment requires internal audit to reduce fine estimate below R700K.'),
    ('Other jurisdictions', 'R2M per jurisdiction', 'Per additional regulated market where company has legal entity (UK, US states, Australia, etc.).'),
    ('ECTA Section 89 (always applied)', 'R1M (cat estimate)', 'Electronic Communications and Transactions Act. Court-discretionary fine plus imprisonment up to 5 years for s86(4)/(5) or s87 contraventions. Applied to any online business processing personal information in catastrophe modelling.'),
    ('CPA Section 112 (B2C flag)', 'max(R1M, rev x 10%)', 'Consumer Protection Act. National Consumer Tribunal may impose 10% of annual turnover or R1M, whichever is greater. Applied when the B2C flag is set. No capacity scaling - the 10% formula already scales naturally.'),
    ('JSE Listings Requirements (listed flag)', 'R7.5M', 'Capacity-scaled. Public censure, fine, director disqualification. SA precedent 2024: Eskom R3M, Tongaat CFO R6M.'),
    ('FIC Act Section 45C (accountable institution)', 'R50M (legal person) cap', 'Capacity-scaled. Auto-applied for FS sub-industries and Legal Services. Applies separately to banks, brokers, attorneys, estate agents, dealers in precious metals, casinos.'),
    ('FSRA Section 167 / FSCA (FS sub-industries)', 'R100M cat assumption', 'Capacity-scaled. No statutory cap exists; R100M model assumption for 1-in-100 view. Largest historical SA penalty was R475M (AYO Technology, 2024).'),
    ('Sector frameworks (industry-keyed)', 'Variable', 'Auto-applied by sub-industry: NHA s17(2) + HPCSA for Health Services; LPC for Legal Services; ECA/ICASA for Telecoms; MHSA for Mining; PFMA for Public Sector. Plus healthcare add-ons: Medical Schemes Act, Pharmacy Act, SAHPRA / Medicines Act.'),
    ('Enterprise Capacity Factor', '0.10 to 1.00', 'Revenue-band scaling applied to all statutory maxima for the catastrophe view: < R10M = 0.10; R10M-R25M = 0.15; R25M-R75M = 0.25; R75M-R200M = 0.45; R200M-R500M = 0.65; R500M-R1B = 0.80; R1B-R10B = 0.95; >= R10B = 1.00. Reflects SA Information Regulator s109(3) "extent and ability" considerations and equivalent regulator enforcement patterns. Without this scaling a R10M FSP would face the same R150M+ cat ceiling as a R200B insurer - indefensible.'),
]

parts.append(make_table(['Jurisdiction', 'Calculation', 'Description', 'Your Value'], rows))

parts.append(f'<w:p w14:paraId="{np()}" w14:textId="77777777" w:rsidR="00A108AD" w:rsidRDefault="00A108AD"><w:pPr><w:spacing w:before="80" w:after="80"/></w:pPr><w:r><w:rPr><w:i/><w:iCs/><w:color w:val="666666"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr><w:t xml:space="preserve">Worked example - R200M listed FS broker (B2C, accountable institution). Capacity factor = 0.65. Cat regulatory stack: POPIA R10M x 0.65 = R6.5M + ECTA R1M x 0.65 = R0.65M + CPA R200M x 10% = R20M + FSCA R100M x 0.65 = R65M + FIC R50M x 0.65 = R32.5M + JSE R7.5M x 0.65 = R4.875M. Total = R129.5M (capacity-scaled). The same entity at R10M revenue (capacity factor 0.15) would face roughly R24M total - reflecting realistic enforcement scale rather than uniform statutory ceilings.</w:t></w:r></w:p>')

with open('section13_xml.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(parts))
print(f'Generated {len(rows)} rows')
