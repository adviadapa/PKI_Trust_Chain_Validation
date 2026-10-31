const validBtn = document.getElementById("validBtn");
const fakeBtn = document.getElementById("fakeBtn");
const summary = document.getElementById("summary");
const checks = document.getElementById("checks");
const certificates = document.getElementById("certificates");

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function render(result, showCertificates) {
  summary.className = "summary " + (result.valid ? "success" : "failure");
  summary.textContent = (result.valid ? "✓ " : "✕ ") + result.message;
  checks.innerHTML = result.checks.map(c => `
    <div class="check ${c.ok ? "ok" : "bad"}">
      <span class="check-icon">${c.ok ? "✓" : "✕"}</span>
      <div><strong>${escapeHtml(c.name)}</strong><small>${escapeHtml(c.detail)}</small></div>
    </div>`).join("");
  if (showCertificates && result.certificate_chain) {
    certificates.innerHTML = result.certificate_chain.map(cert => `
      <article class="cert">
        <h3>${escapeHtml(cert.level)}</h3>
        <p><b>Subject</b><br>${escapeHtml(cert.subject)}</p>
        <p><b>Issuer</b><br>${escapeHtml(cert.issuer)}</p>
        <p><b>Serial</b><br>${escapeHtml(cert.serial)}</p>
      </article>`).join("");
  }
}
async function run(path, button, includeCerts) {
  validBtn.disabled = fakeBtn.disabled = true;
  summary.className = "summary empty";
  summary.textContent = "Validating certificates…";
  checks.innerHTML = "";
  try {
    const response = await fetch(path);
    if (!response.ok) throw new Error("Server returned " + response.status);
    render(await response.json(), includeCerts);
  } catch (error) {
    summary.className = "summary failure";
    summary.textContent = "Could not connect to the backend. Make sure Flask is running. " + error.message;
  } finally {
    validBtn.disabled = fakeBtn.disabled = false;
  }
}
validBtn.addEventListener("click", () => run("/api/validate", validBtn, true));
fakeBtn.addEventListener("click", () => run("/api/validate-tampered", fakeBtn, false));
