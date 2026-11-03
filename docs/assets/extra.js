// secpatch documentation — custom JavaScript
document.addEventListener("DOMContentLoaded", () => {
  // Copy-to-clipboard buttons on code blocks
  document.querySelectorAll("pre.code").forEach((block) => {
    const btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.textContent = "Copy";
    btn.style.cssText =
      "float:right;margin-top:0.5rem;padding:0.25rem 0.75rem;font-size:0.75rem;background:var(--md-primary-fg-color);color:#fff;border:none;border-radius:4px;cursor:pointer;opacity:0.7;";
    btn.addEventListener("click", () => {
      const code = block.querySelector("code");
      if (!code) return;
      navigator.clipboard.writeText(code.innerText);
      const old = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = old), 1500);
    });
    block.style.position = "relative";
    block.appendChild(btn);
  });
});
