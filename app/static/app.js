// Confirm destructive actions: <form data-confirm="Delete this?">
document.addEventListener("submit", (e) => {
  const msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
document.addEventListener("click", (e) => {
  if (e.target.closest("[data-print]")) window.print();
});
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-confirm-click]");
  if (b && !window.confirm(b.getAttribute("data-confirm-click"))) e.preventDefault();
});
