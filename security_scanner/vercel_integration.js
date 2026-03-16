/**
 * Cyber Insurance Security Scanner — Vercel/frontend integration
 * Drop this into your existing script.js or import as a module.
 *
 * Usage:
 *   const result = await runSecurityScan('example.co.za');
 *   fillQuoteFields(result);
 *
 * Set SCANNER_BASE_URL to wherever you deploy the Flask service
 * (e.g. https://scanner.yourcompany.com or http://localhost:5001).
 */

const SCANNER_BASE_URL = "http://localhost:5001"; // ← update for production

/**
 * Start a scan and poll until complete (or timeout).
 * @param {string} domain
 * @param {number} pollIntervalMs
 * @param {number} maxWaitMs
 * @returns {Promise<object>} Full scan result JSON
 */
async function runSecurityScan(domain, pollIntervalMs = 3000, maxWaitMs = 120000) {
  // 1. Start scan
  const startRes = await fetch(`${SCANNER_BASE_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain }),
  });
  if (!startRes.ok) {
    const err = await startRes.json().catch(() => ({}));
    throw new Error(`Failed to start scan: ${err.error || startRes.status}`);
  }
  const { scan_id } = await startRes.json();

  // 2. Poll for results
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollIntervalMs));

    const pollRes = await fetch(`${SCANNER_BASE_URL}/api/scan/${scan_id}`);
    if (pollRes.status === 202) continue; // still pending

    if (!pollRes.ok) {
      const err = await pollRes.json().catch(() => ({}));
      throw new Error(`Scan failed: ${err.error || pollRes.status}`);
    }
    return await pollRes.json();
  }
  throw new Error("Scan timed out after " + maxWaitMs / 1000 + "s");
}

/**
 * Map scan results to risk premium multipliers for quoting.
 * Returns an object you can use to adjust your base premium.
 */
function extractRiskFactors(scanResult) {
  const cats = scanResult.categories || {};
  return {
    overallScore: scanResult.overall_risk_score,       // 0-1000, higher = more risk
    riskLevel: scanResult.risk_level,                  // Low / Medium / High / Critical
    sslGrade: cats.ssl?.grade ?? "?",
    sslExpired: cats.ssl?.certificate?.is_expired ?? false,
    emailScore: cats.email_security?.score ?? 0,       // 0-10
    dmarcPolicy: cats.email_security?.dmarc?.policy,  // none | quarantine | reject
    breachCount: cats.breaches?.breach_count ?? 0,
    highRiskPorts: (cats.dns_infrastructure?.open_ports ?? [])
      .filter((p) => p.risk === "high")
      .map((p) => p.port),
    httpsEnforced: cats.website_security?.https_enforced ?? false,
    headerScore: cats.http_headers?.score ?? 0,         // 0-100
    recommendations: scanResult.recommendations ?? [],
    reportUrl: `${SCANNER_BASE_URL}/results/${scanResult.scan_id}`,
  };
}

/**
 * Example: compute a simple loading multiplier for a cyber quote.
 * Replace with your actual underwriting logic.
 */
function computePremiumMultiplier(factors) {
  let multiplier = 1.0;

  // Critical risk → large loading
  if (factors.riskLevel === "Critical") multiplier += 0.50;
  else if (factors.riskLevel === "High") multiplier += 0.25;
  else if (factors.riskLevel === "Medium") multiplier += 0.10;

  // Expired SSL cert → extra loading
  if (factors.sslExpired) multiplier += 0.15;

  // Many breaches → significant loading
  if (factors.breachCount > 10) multiplier += 0.30;
  else if (factors.breachCount > 3) multiplier += 0.15;
  else if (factors.breachCount > 0) multiplier += 0.05;

  // High-risk open ports
  multiplier += factors.highRiskPorts.length * 0.05;

  // No DMARC enforcement
  if (!factors.dmarcPolicy || factors.dmarcPolicy === "none") multiplier += 0.10;

  return parseFloat(multiplier.toFixed(2));
}

// Export for use in other modules (remove if using plain <script> tags)
if (typeof module !== "undefined") {
  module.exports = { runSecurityScan, extractRiskFactors, computePremiumMultiplier };
}
