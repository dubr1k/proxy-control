import { esc, query } from "./common.js";

export function qrCard(source, label, filename = "proxy-control-qr.svg", imageClass = "link-qr") {
  return `<figure class="qr-card">
    <button type="button" class="qr-preview" data-qr-expand data-qr-filename="${esc(filename)}" aria-label="Увеличить QR">
      <img class="${esc(imageClass)}" src="${esc(source)}" alt="${esc(label)}">
    </button>
    <figcaption>${esc(label)}</figcaption>
    <a class="secondary button" href="${esc(source)}" download="${esc(filename)}">Скачать QR</a>
  </figure>`;
}

// A shared presentation for the first issuance and every subsequent reveal.
export function awgConfigCard({ value, qr, label, username }) {
  return `<div class="config-delivery">
    ${qr ? qrCard(qr, `QR-код конфига: ${username}`, `${username}.svg`) : ""}
    <div class="config-delivery-actions">
      <p class="form-hint">Отсканируйте QR в AmneziaWG или AmneziaVPN либо импортируйте файл .conf.</p>
      <span class="link-card-actions"><a class="primary button" href="data:text/plain;charset=utf-8,${encodeURIComponent(value)}" download="${esc(username)}.conf">Скачать .conf</a>
        <button type="button" class="secondary button copy" data-copy="${esc(value)}">Копировать</button></span>
      <details class="config-source"><summary>Посмотреть конфигурацию</summary>
        <label class="grant-link-field">${esc(label)}<textarea class="awg-conf" readonly rows="10" spellcheck="false" aria-label="${esc(label)}">${esc(value)}</textarea></label>
      </details>
    </div>
  </div>`;
}

export function bindQrViewer(root, openModal) {
  const dialog = query("#qr-modal", root);
  if (!dialog) return;
  let owner = null;
  query("#qr-large-download", root).addEventListener("click", () => {
    owner?.dispatchEvent(new Event("qr-download"));
  });
  root.addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-qr-expand]");
    const image = button?.querySelector("img");
    // Only the panel's local SVG payloads belong in this viewer.
    if (!image || !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/.test(image.getAttribute("src") || "")) return;
    owner = button.closest("dialog");
    query("#qr-large", root).src = image.src;
    query("#qr-large", root).alt = image.alt;
    const download = query("#qr-large-download", root);
    download.href = image.src;
    download.download = button.dataset.qrFilename || "proxy-control-qr.svg";
    openModal("#qr-modal");
  });
  dialog.addEventListener("close", () => {
    if (dialog.open) return;
    query("#qr-large", root).removeAttribute("src");
    query("#qr-large", root).alt = "";
    query("#qr-large-download", root).removeAttribute("href");
    query("#qr-large-download", root).removeAttribute("download");
    owner = null;
  });
  root.addEventListener("close", (event) => {
    if (event.target === owner && !owner.open && dialog.open) dialog.close();
  }, true);
}
