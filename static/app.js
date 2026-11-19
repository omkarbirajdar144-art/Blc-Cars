(() => {
  const form = document.getElementById("scanForm");
  const button = document.getElementById("scanBtn");
  const target = document.getElementById("target");

  if (form && button) {
    form.addEventListener("submit", () => {
      if (!target.value.trim()) return;
      button.disabled = true;
      button.innerHTML = '<span class="btn-icon">◌</span> Scanning target…';
    });
  }

  const score = document.getElementById("scoreNumber");
  if (score) {
    const finalValue = Math.max(0, Math.min(100, Number(score.textContent) || 0));
    let current = 0;
    const duration = 650;
    const started = performance.now();
    const tick = (now) => {
      const progress = Math.min(1, (now - started) / duration);
      current = Math.round(finalValue * progress);
      score.textContent = String(current);
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
})();