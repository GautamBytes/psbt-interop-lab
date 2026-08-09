(() => {
  const stored = window.localStorage.getItem("psbt-lab-theme");
  const theme =
    stored === "dark" || stored === "light"
      ? stored
      : window.matchMedia?.("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark";
  document.documentElement.dataset.theme = theme;
})();
