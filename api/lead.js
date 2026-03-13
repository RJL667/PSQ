import nodemailer from 'nodemailer';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

    const {
      revenueBand,
      coverLimit,
      annualPremium,
      monthlyPremium,
      mdrComplete,
      turnoverOver250M,
      companyName,
      tradingAs,
      reseller,
      contactPerson,
      contactNumber,
      email,
      employees,
      industry
    } = body || {};

    // Basic required-field check
    const required = {
      companyName,
      contactPerson,
      contactNumber,
      email,
      revenueBand,
      coverLimit
    };
    for (const [k, v] of Object.entries(required)) {
      if (!v || String(v).trim() === '') {
        return res.status(400).json({ ok: false, error: `Missing field: ${k}` });
      }
    }

    const to = process.env.LEAD_TO_EMAIL || 'SophosMDR@phishield.com';
    const from = process.env.LEAD_FROM_EMAIL;

    if (!from) {
      return res.status(500).json({
        ok: false,
        error: 'Server email not configured (missing LEAD_FROM_EMAIL).'
      });
    }

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const subject = `Phishield Cyber Cover Lead – ${companyName}`;

    const text =
      `QUOTE DETAILS\n` +
      `──────────────────\n` +
      `Revenue Band:       ${revenueBand}\n` +
      `Cover Limit:        ${coverLimit}\n` +
      `Annual Premium:     ${annualPremium || ''}\n` +
      `Monthly Premium:    ${monthlyPremium || ''}\n` +
      `MDR Complete:       ${mdrComplete || ''}\n` +
      `Turnover >R250M:    ${turnoverOver250M || ''}\n\n` +
      `CONTACT DETAILS\n` +
      `──────────────────\n` +
      `Company Name:       ${companyName}\n` +
      `Trading As:         ${tradingAs || ''}\n` +
      `Reseller:           ${reseller || ''}\n` +
      `Contact Person:     ${contactPerson}\n` +
      `Contact Number:     ${contactNumber}\n` +
      `Email:              ${email}\n` +
      `No. of Employees:   ${employees || ''}\n` +
      `Industry:           ${industry || ''}\n`;

    await transporter.sendMail({
      to,
      from,
      replyTo: email, // so replying goes to the lead
      subject,
      text
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: err?.message || String(err)
    });
  }
}
