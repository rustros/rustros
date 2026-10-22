"use strict";
// language (zh / en), remembered; copy buttons on commands
const html = document.documentElement, langBtn = document.getElementById("lang");
function setLang(l) {
  html.lang = l;
  if (langBtn) langBtn.textContent = l === "zh" ? "EN" : "中文";
  try { localStorage.setItem("lang", l); } catch (e) {}
}
let saved = null;
try { saved = localStorage.getItem("lang"); } catch (e) {}
setLang(saved || ((navigator.language || "").toLowerCase().startsWith("zh") ? "zh" : "en"));
if (langBtn) langBtn.onclick = () => setLang(html.lang === "zh" ? "en" : "zh");
for (const box of document.querySelectorAll(".cmd")) {
  const b = document.createElement("button");
  b.className = "copy"; b.type = "button"; b.textContent = "copy";
  b.onclick = () => {
    const t = box.querySelector("pre").innerText;
    (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(
      () => { b.textContent = "✓"; setTimeout(() => b.textContent = "copy", 1500); },
      () => { const r = document.createRange(); r.selectNodeContents(box.querySelector("pre")); getSelection().removeAllRanges(); getSelection().addRange(r); });
  };
  box.appendChild(b);
}
// the latest release, where a page wants it
async function latest() {
  const r = await fetch("/releases/latest.json", { cache: "no-cache" });
  if (!r.ok) throw r.status;
  return r.json();
}
function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]); }
function both(zh, en) { return `<span data-l="zh">${zh}</span><span data-l="en">${en}</span>`; }
