// Own lightweight SVG charts for the monitoring screen (Proxy Control 2.0). No libraries, and
// nothing the CSP (`style-src 'self'`) would drop: colours come from CSS classes and custom
// properties (`--chart-1…8`, `--proto-*`), geometry from SVG attributes, and the few pixel
// positions of the tooltip go through the CSSOM.
//
// Every chart is fed ALIGNED arrays — one shared time axis `x` (epoch seconds) and per series
// an array of the same length where `null` means «no data». A `null` (or a hole longer than
// 2.5 typical steps) breaks the line: gaps stay gaps, they are never drawn as zeros or bridged.
import { esc, locale } from "./common.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const BASE = 1024;
const RATE_UNITS = ["Б/с", "КБ/с", "МБ/с", "ГБ/с", "ТБ/с"];
const BYTE_UNITS = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"];
const SR_ROWS = 24; // the hidden data table is a sampled summary, not a dump
const SR_REFRESH_MS = 5000;
let uid = 0;

// -- number formatting -------------------------------------------------------------------------

function decimal(text) {
  return locale() === "en-GB" ? text : text.replace(".", ",");
}

function scaled(value, units) {
  let amount = Math.max(0, Number(value) || 0);
  let unit = 0;
  while (unit < units.length - 1 && amount >= BASE) {
    amount /= BASE;
    unit += 1;
  }
  return { amount, unit };
}

function digits(amount, unit) {
  if (unit === 0) return 0;
  return amount < 10 ? 2 : amount < 100 ? 1 : 0;
}

// Network rates are bytes per second (KB = 1024, as everywhere in the panel).
export function formatRate(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  const { amount, unit } = scaled(value, RATE_UNITS);
  return `${decimal(amount.toFixed(digits(amount, unit)))} ${RATE_UNITS[unit]}`;
}

export function formatBytes(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  const { amount, unit } = scaled(value, BYTE_UNITS);
  return `${decimal(amount.toFixed(digits(amount, unit)))} ${BYTE_UNITS[unit]}`;
}

export function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  const amount = Number(value);
  return `${decimal(amount.toFixed(amount < 10 ? 1 : 0))} %`;
}

const FORMATTERS = {
  rate: formatRate,
  bytes: formatBytes,
  percent: formatPercent,
  load: (value) => (value === null || value === undefined ? "—" : decimal(Number(value).toFixed(2))),
  count: (value) => (value === null || value === undefined ? "—" : String(Math.round(Number(value)))),
};

function formatter(options) {
  return options.format || FORMATTERS[options.unit] || FORMATTERS.count;
}

// -- scales ------------------------------------------------------------------------------------

// A «nice» step (1, 2, 2.5, 5 × 10^k) that gives about `count` intervals up to `max`.
export function niceStep(max, count = 4) {
  if (!(max > 0)) return 1;
  const rough = max / count;
  const power = 10 ** Math.floor(Math.log10(rough));
  const unit = rough / power;
  const factor = unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 2.5 ? 2.5 : unit <= 5 ? 5 : 10;
  return factor * power;
}

export function niceTicks(max, count = 4) {
  const step = niceStep(max, count);
  const top = Math.max(step, Math.ceil(max / step - 1e-9) * step);
  const ticks = [];
  for (let value = 0; value <= top + step / 1000; value += step) ticks.push(Number(value.toPrecision(12)));
  return { ticks, max: top, step };
}

// Rate axes are scaled by the binary unit the top of the data lives in, so the labels read
// «0 · 5 · 10 МБ/с» rather than 10485760.
export function rateTicks(max, count = 4) {
  const safe = Math.max(Number(max) || 0, BASE);
  const unit = Math.min(RATE_UNITS.length - 1, Math.floor(Math.log(safe) / Math.log(BASE)));
  const factor = BASE ** unit;
  const nice = niceTicks(safe / factor, count);
  return { ticks: nice.ticks.map((tick) => tick * factor), max: nice.max * factor, unit, factor, name: RATE_UNITS[unit] };
}

export function byteTicks(max, count = 4) {
  const safe = Math.max(Number(max) || 0, 1);
  const unit = Math.min(BYTE_UNITS.length - 1, Math.floor(Math.log(safe) / Math.log(BASE)));
  const factor = BASE ** unit;
  const nice = niceTicks(safe / factor, count);
  return { ticks: nice.ticks.map((tick) => tick * factor), max: nice.max * factor, unit, factor, name: BYTE_UNITS[unit] };
}

function trimNumber(value) {
  return decimal(String(Number(value.toFixed(2))));
}

// Axis description for a unit: tick values, the top of the axis and how to print a tick.
export function yAxis(options, dataMax) {
  const unit = options.unit || "count";
  if (unit === "percent") {
    if (options.yMax === "auto") {
      const nice = niceTicks(Math.min(100, Math.max(10, dataMax * 1.15)), 4);
      const max = Math.min(100, nice.max);
      return { ticks: nice.ticks.filter((tick) => tick <= max + 1e-9), max, label: (tick) => `${trimNumber(tick)}%` };
    }
    return { ticks: [0, 25, 50, 75, 100], max: 100, label: (tick) => `${tick}%` };
  }
  const wanted = options.yMax && options.yMax !== "auto" ? Math.max(options.yMax, dataMax) : dataMax * 1.08;
  if (unit === "rate" || unit === "bytes") {
    const axis = unit === "rate" ? rateTicks(wanted) : byteTicks(wanted);
    const last = axis.ticks.length - 1;
    return {
      ticks: axis.ticks,
      max: axis.max,
      label: (tick, index) => (index === last ? `${trimNumber(tick / axis.factor)} ${axis.name}` : trimNumber(tick / axis.factor)),
    };
  }
  const nice = niceTicks(Math.max(wanted, unit === "load" ? 1 : 1), 4);
  return { ticks: nice.ticks, max: nice.max, label: (tick) => trimNumber(tick) };
}

const TIME_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800, 1209600, 2592000];

// Ticks on «round» local times: every 5 minutes, every 6 hours, at midnight…
export function timeTicks(from, to, count, offsetSeconds = -new Date().getTimezoneOffset() * 60) {
  const span = to - from;
  if (!(span > 0)) return [];
  const step = TIME_STEPS.find((candidate) => span / candidate <= count) || TIME_STEPS[TIME_STEPS.length - 1];
  const ticks = [];
  for (let tick = Math.ceil((from + offsetSeconds) / step) * step - offsetSeconds; tick <= to + 1e-6; tick += step) ticks.push(tick);
  ticks.step = step;
  return ticks;
}

function formatClock(seconds, withSeconds) {
  return new Date(seconds * 1000).toLocaleTimeString(locale(), withSeconds
    ? { hour: "2-digit", minute: "2-digit", second: "2-digit" }
    : { hour: "2-digit", minute: "2-digit" });
}

function formatDay(seconds) {
  return new Date(seconds * 1000).toLocaleDateString(locale(), { day: "numeric", month: "short" });
}

export function timeLabel(seconds, span, long = false) {
  if (span >= 2 * 86400) return long ? `${formatDay(seconds)}, ${formatClock(seconds, false)}` : formatDay(seconds);
  if (span > 86400) return long ? `${formatDay(seconds)}, ${formatClock(seconds, false)}` : `${formatDay(seconds)} ${formatClock(seconds, false)}`;
  return formatClock(seconds, long && span <= 3600);
}

// -- data helpers ------------------------------------------------------------------------------

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

// Runs of consecutive indices that may be joined by a line: a `null` value or a hole in time
// (more than `maxGap` seconds between neighbours) ends a run.
export function splitSegments(x, values, maxGap = Infinity) {
  const runs = [];
  let run = [];
  for (let index = 0; index < x.length; index += 1) {
    const value = values[index];
    const valid = value !== null && value !== undefined && Number.isFinite(Number(value));
    const hole = run.length && x[index] - x[run[run.length - 1]] > maxGap;
    if (!valid || hole) {
      if (run.length) runs.push(run);
      run = [];
    }
    if (valid) run.push(index);
  }
  if (run.length) runs.push(run);
  return runs;
}

export function defaultGap(x) {
  const steps = [];
  for (let index = 1; index < x.length; index += 1) if (x[index] > x[index - 1]) steps.push(x[index] - x[index - 1]);
  return median(steps) * 2.5 || Infinity;
}

// Several `{id: [[ts, avg, max], …]}` series with their own timestamps → one shared axis
// (`x`) and per id an array with `null` where that series has no bucket.
export function alignSeries(raw, column = 1) {
  const stamps = new Set();
  for (const points of Object.values(raw || {})) for (const point of points || []) stamps.add(point[0]);
  const x = [...stamps].sort((a, b) => a - b);
  const slot = new Map(x.map((stamp, index) => [stamp, index]));
  const series = {};
  for (const [id, points] of Object.entries(raw || {})) {
    const values = new Array(x.length).fill(null);
    for (const point of points || []) {
      const value = point[column];
      if (value !== null && value !== undefined) values[slot.get(point[0])] = Number(value);
    }
    series[id] = values;
  }
  return { x, series };
}

// «Straight» or a monotone cubic (Fritsch–Carlson): smooth, but it never overshoots the data,
// so a curve cannot dip below zero or invent a peak.
export function monotonePath(points) {
  if (!points.length) return "";
  const first = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  if (points.length < 3) return points.slice(1).reduce((path, point) => `${path}L${point[0].toFixed(1)},${point[1].toFixed(1)}`, first);
  const count = points.length;
  const slopes = [];
  const tangents = new Array(count).fill(0);
  for (let index = 0; index < count - 1; index += 1) {
    const dx = points[index + 1][0] - points[index][0];
    slopes.push(dx === 0 ? 0 : (points[index + 1][1] - points[index][1]) / dx);
  }
  tangents[0] = slopes[0];
  tangents[count - 1] = slopes[count - 2];
  for (let index = 1; index < count - 1; index += 1) {
    tangents[index] = slopes[index - 1] * slopes[index] <= 0 ? 0 : (slopes[index - 1] + slopes[index]) / 2;
  }
  for (let index = 0; index < count - 1; index += 1) {
    if (slopes[index] === 0) {
      tangents[index] = 0;
      tangents[index + 1] = 0;
      continue;
    }
    const a = tangents[index] / slopes[index];
    const b = tangents[index + 1] / slopes[index];
    const size = a * a + b * b;
    if (size > 9) {
      const scale = 3 / Math.sqrt(size);
      tangents[index] = scale * a * slopes[index];
      tangents[index + 1] = scale * b * slopes[index];
    }
  }
  let path = first;
  for (let index = 0; index < count - 1; index += 1) {
    const dx = (points[index + 1][0] - points[index][0]) / 3;
    path += `C${(points[index][0] + dx).toFixed(1)},${(points[index][1] + dx * tangents[index]).toFixed(1)},`
      + `${(points[index + 1][0] - dx).toFixed(1)},${(points[index + 1][1] - dx * tangents[index + 1]).toFixed(1)},`
      + `${points[index + 1][0].toFixed(1)},${points[index + 1][1].toFixed(1)}`;
  }
  return path;
}

function linearPath(points) {
  return points.reduce((path, point, index) => `${path}${index ? "L" : "M"}${point[0].toFixed(1)},${point[1].toFixed(1)}`, "");
}

// -- DOM plumbing ------------------------------------------------------------------------------

function make(tag, className, parent) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  parent?.append(node);
  return node;
}

function makeSvg(tag, attributes = {}, parent) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  parent?.append(node);
  return node;
}

// One ResizeObserver for all charts: dozens of sparklines would otherwise own one each.
let observer = null;
const watched = new Map();
function watch(element, callback) {
  if (typeof ResizeObserver === "undefined") return () => {};
  observer ||= new ResizeObserver((entries) => {
    // drawn on the next frame: resizing inside the observer's own callback raises the browser's
    // «ResizeObserver loop» error
    for (const entry of entries) {
      const callback = watched.get(entry.target);
      if (callback) window.requestAnimationFrame(() => callback(entry.contentRect.width));
    }
  });
  watched.set(element, callback);
  observer.observe(element);
  return () => {
    watched.delete(element);
    observer.unobserve(element);
  };
}

function seriesClass(series, index) {
  return series.cls || `ser-${(index % 8) + 1}`;
}

function finite(value) {
  return value !== null && value !== undefined && Number.isFinite(Number(value));
}

function spanOf(domain) {
  return domain[1] - domain[0];
}

function describe(options, x, series, format) {
  const parts = series.map((entry) => {
    const values = entry.values.filter(finite);
    if (!values.length) return `${entry.label}: нет данных`;
    const last = [...entry.values].reverse().find(finite);
    return `${entry.label}: сейчас ${format(last)}, максимум ${format(Math.max(...values))}`;
  });
  const span = x.length ? timeLabel(x[0], 0, true).concat(" – ", timeLabel(x[x.length - 1], 0, true)) : "";
  return `${options.label || "График"}${span ? ` (${span})` : ""}. ${parts.join("; ")}`;
}

// -- the shared XY chart (line, area, stacked area, bars) --------------------------------------

function xyChart(container, kind, initial) {
  const id = `ch${(uid += 1)}`;
  let options = { ...initial };
  let width = container.clientWidth || options.width || 640;
  let hover = null; // an index into x (or category), set by the pointer or the keyboard
  let hoverT = null; // the timestamp it points at: a live chart shifts its indices every tick
  let pointerInside = false;
  let lastTable = 0;
  let model = null;

  const root = make("div", `chart chart-${kind}`, container);
  const svg = makeSvg("svg", { class: "chart-svg", role: "img", tabindex: "0", focusable: "true" }, root);
  const tip = make("div", "chart-tip", root);
  tip.hidden = true;
  const legend = make("div", "chart-legend", root);
  const live = make("div", "chart-sr", root);
  live.setAttribute("aria-live", "polite");
  const table = make("table", "chart-sr", root);

  const margin = () => {
    const axis = model?.axis;
    const labels = axis ? axis.ticks.map((tick, index) => axis.label(tick, index)) : ["0"];
    const widest = Math.max(...labels.map((text) => text.length), 2);
    return { top: 10, right: 12, bottom: kind === "bars" ? 24 : 22, left: Math.min(78, Math.round(widest * 6.1 + 16)) };
  };

  function compute() {
    const seriesList = (options.series || []).map((entry, index) => ({ ...entry, cls: seriesClass(entry, index) }));
    const bars = kind === "bars";
    const x = bars ? (options.categories || []).map((_, index) => index) : options.x || [];
    const domain = bars ? [-0.5, Math.max(x.length - 0.5, 0.5)] : options.domain || [x[0] ?? 0, x[x.length - 1] ?? 1];
    if (!(domain[1] > domain[0])) domain[1] = domain[0] + 1;
    const stacked = kind === "stacked" || (bars && options.stacked !== false);
    const gap = bars ? Infinity : options.gap ?? defaultGap(x);
    let dataMax = 0;
    const totals = x.map((_, index) => seriesList.reduce((sum, entry) => sum + (finite(entry.values[index]) ? Number(entry.values[index]) : 0), 0));
    if (stacked) dataMax = Math.max(0, ...totals);
    else for (const entry of seriesList) for (const value of entry.values) if (finite(value)) dataMax = Math.max(dataMax, Number(value));
    const axis = yAxis(options, dataMax);
    return { seriesList, x, domain, stacked, gap, axis, totals, bars };
  }

  function layout() {
    const m = margin();
    const height = options.height || 190;
    return { m, height, plotW: Math.max(40, width - m.left - m.right), plotH: Math.max(40, height - m.top - m.bottom) };
  }

  function draw() {
    model = compute();
    const lay = layout();
    const { m, height, plotW, plotH } = lay;
    const { seriesList, x, domain, stacked, gap, axis, totals, bars } = model;
    const sx = (value) => m.left + ((value - domain[0]) / (domain[1] - domain[0])) * plotW;
    const sy = (value) => m.top + plotH - (Math.min(value, axis.max) / axis.max) * plotH;
    model.sx = sx;
    model.sy = sy;
    model.lay = lay;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", String(width));
    svg.setAttribute("height", String(height));

    const format = formatter(options);
    let markup = `<defs><clipPath id="${id}-clip"><rect x="${m.left}" y="${m.top - 2}" width="${plotW}" height="${plotH + 4}"/></clipPath>`;
    if (kind === "area") {
      seriesList.forEach((entry, index) => {
        markup += `<linearGradient id="${id}-g${index}" class="${entry.cls}" x1="0" y1="0" x2="0" y2="1"><stop class="gs gs-top" offset="0"/><stop class="gs gs-bottom" offset="1"/></linearGradient>`;
      });
    }
    markup += "</defs>";

    // grid + y labels
    markup += '<g class="chart-grid">';
    for (const tick of axis.ticks) markup += `<line x1="${m.left}" x2="${m.left + plotW}" y1="${sy(tick).toFixed(1)}" y2="${sy(tick).toFixed(1)}"${tick === 0 ? ' class="chart-base"' : ""}/>`;
    markup += "</g><g class=\"chart-ticks\">";
    axis.ticks.forEach((tick, index) => {
      markup += `<text class="chart-tick" x="${m.left - 8}" y="${(sy(tick) + 3.5).toFixed(1)}" text-anchor="end">${esc(axis.label(tick, index))}</text>`;
    });
    // x labels
    if (bars) {
      const every = plotW / x.length < 18 ? 3 : 1;
      (options.categories || []).forEach((name, index) => {
        if (index % every === 0) markup += `<text class="chart-tick" x="${sx(index).toFixed(1)}" y="${height - 6}" text-anchor="middle">${esc(name)}</text>`;
      });
    } else {
      const ticks = timeTicks(domain[0], domain[1], Math.max(2, Math.floor(plotW / 84)));
      const span = spanOf(domain);
      ticks.forEach((tick, index) => {
        const anchor = index === 0 && sx(tick) - m.left < 22 ? "start" : width - sx(tick) < 26 ? "end" : "middle";
        markup += `<line class="chart-xtick" x1="${sx(tick).toFixed(1)}" x2="${sx(tick).toFixed(1)}" y1="${m.top + plotH}" y2="${m.top + plotH + 3}"/>`;
        markup += `<text class="chart-tick" x="${sx(tick).toFixed(1)}" y="${height - 6}" text-anchor="${anchor}">${esc(ticks.step < 60 ? formatClock(tick, true) : timeLabel(tick, span))}</text>`;
      });
    }
    markup += '</g><g clip-path="url(#' + id + '-clip)" class="chart-data">';

    const points = (values) => x.map((stamp, index) => [sx(stamp), finite(values[index]) ? sy(Number(values[index])) : null]);

    if (bars) {
      const slot = plotW / Math.max(x.length, 1);
      const barWidth = Math.max(2, Math.min(28, slot * 0.68));
      x.forEach((_, index) => {
        let base = 0;
        seriesList.forEach((entry) => {
          const value = finite(entry.values[index]) ? Number(entry.values[index]) : 0;
          if (value <= 0) return;
          const top = stacked ? base + value : value;
          const y0 = sy(stacked ? base : 0);
          const y1 = sy(top);
          const size = Math.max(0, y0 - y1);
          const radius = Math.min(3, size / 2, barWidth / 2);
          // the data end (top) of the last segment is rounded; the bottom sits on the baseline
          markup += `<rect class="chart-bar ${entry.cls}" x="${(sx(index) - barWidth / 2).toFixed(1)}" y="${y1.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${size.toFixed(1)}" rx="${radius.toFixed(1)}"/>`;
          base = top;
        });
      });
    } else if (stacked) {
      // bands are drawn bottom-up; a missing value counts as 0 inside a band, and a moment
      // where EVERY series is missing is a hole in the data
      const alive = x.map((_, index) => seriesList.some((entry) => finite(entry.values[index])) ? 1 : null);
      const runs = splitSegments(x, alive, gap);
      const lower = new Array(x.length).fill(0);
      seriesList.forEach((entry) => {
        const upper = lower.map((base, index) => base + (finite(entry.values[index]) ? Number(entry.values[index]) : 0));
        for (const run of runs) {
          if (run.length < 2) continue;
          const top = run.map((index) => [sx(x[index]), sy(upper[index])]);
          const bottom = run.map((index) => [sx(x[index]), sy(lower[index])]).reverse();
          const line = linearPath(top);
          markup += `<path class="chart-band ${entry.cls}" d="${line}${bottom.map((point) => `L${point[0].toFixed(1)},${point[1].toFixed(1)}`).join("")}Z"/>`;
          markup += `<path class="chart-line ${entry.cls}" d="${line}"/>`;
        }
        for (let index = 0; index < x.length; index += 1) lower[index] = upper[index];
      });
    } else {
      seriesList.forEach((entry, index) => {
        const coords = points(entry.values);
        for (const run of splitSegments(x, entry.values, gap)) {
          const run2 = run.map((position) => coords[position]);
          if (run2.length === 1) {
            markup += `<circle class="chart-lone ${entry.cls}" cx="${run2[0][0].toFixed(1)}" cy="${run2[0][1].toFixed(1)}" r="2"/>`;
            continue;
          }
          const line = options.smooth === false ? linearPath(run2) : monotonePath(run2);
          if (kind === "area" && !entry.noArea) {
            const floor = sy(0);
            markup += `<path class="chart-fill" fill="url(#${id}-g${index})" d="${line}L${run2[run2.length - 1][0].toFixed(1)},${floor.toFixed(1)}L${run2[0][0].toFixed(1)},${floor.toFixed(1)}Z"/>`;
          }
          markup += `<path class="chart-line ${entry.cls}${entry.dash ? " dash" : ""}" d="${line}"/>`;
        }
      });
    }
    markup += "</g>";
    // hover layer: re-created with the rest, kept hidden until there is a hover index
    markup += `<g class="chart-hover" hidden><line class="chart-cross" y1="${m.top}" y2="${m.top + plotH}"/>`;
    if (!bars) seriesList.forEach((entry) => { markup += `<circle class="chart-dot ${entry.cls}" r="4" hidden/>`; });
    markup += `</g><rect class="chart-hit" x="${m.left}" y="${m.top}" width="${plotW}" height="${plotH}"/>`;
    svg.innerHTML = markup;

    svg.setAttribute("aria-label", describe(options, x, seriesList, format));
    drawLegend(format);
    maybeTable(format, false);
    if (hover !== null && hoverT !== null && !bars && x.length) {
      let best = 0;
      for (let index = 1; index < x.length; index += 1) if (Math.abs(x[index] - hoverT) < Math.abs(x[best] - hoverT)) best = index;
      hover = best;
    }
    if (hover !== null && hover < x.length) showHover(hover, false);
    else hideHover();
    void totals;
  }

  function drawLegend(format) {
    const list = model.seriesList;
    legend.hidden = options.legend === false || list.length < 2 && !options.legend;
    if (legend.hidden) return;
    legend.innerHTML = list.map((entry, index) => {
      const index2 = hover !== null && hover < model.x.length ? hover : null;
      const lastValue = index2 !== null ? entry.values[index2] : [...entry.values].reverse().find(finite);
      return `<span class="chart-legend-item" data-series="${index}"><i class="chip ${entry.cls}${entry.dash ? " dashed" : ""}"></i><span>${esc(entry.label)}</span>`
        + (options.legendValues === false ? "" : `<b>${finite(lastValue) ? esc(format(lastValue)) : "—"}</b>`) + "</span>";
    }).join("");
  }

  function maybeTable(format, force) {
    const now = Date.now();
    if (!force && now - lastTable < SR_REFRESH_MS && table.firstChild) return;
    lastTable = now;
    const { x, seriesList, bars } = model;
    const step = Math.max(1, Math.ceil(x.length / SR_ROWS));
    let html = `<caption>${esc(options.label || "График")}</caption><thead><tr><th>${bars ? "" : "Время"}</th>${seriesList.map((entry) => `<th>${esc(entry.label)}</th>`).join("")}</tr></thead><tbody>`;
    for (let index = 0; index < x.length; index += step) {
      const name = bars ? (options.categories || [])[index] : timeLabel(x[index], spanOf(model.domain), true);
      html += `<tr><th>${esc(name)}</th>${seriesList.map((entry) => `<td>${finite(entry.values[index]) ? esc(format(entry.values[index])) : "—"}</td>`).join("")}</tr>`;
    }
    table.innerHTML = `${html}</tbody>`;
  }

  function hideHover() {
    tip.hidden = true;
    svg.querySelector(".chart-hover")?.setAttribute("hidden", "");
  }

  function nearest(position) {
    const { x, sx, bars, domain } = model;
    if (!x.length) return null;
    if (bars) return Math.max(0, Math.min(x.length - 1, Math.round(((position - sx(0)) / (sx(1) - sx(0))) || 0)));
    const target = domain[0] + ((position - model.lay.m.left) / model.lay.plotW) * (domain[1] - domain[0]);
    let low = 0;
    let high = x.length - 1;
    while (high - low > 1) {
      const middle = (low + high) >> 1;
      if (x[middle] < target) low = middle; else high = middle;
    }
    return Math.abs(x[low] - target) <= Math.abs(x[high] - target) ? low : high;
  }

  function showHover(index, announce) {
    const { x, seriesList, sx, sy, stacked, lay, bars, domain } = model;
    hover = index;
    hoverT = index === null ? null : x[index] ?? null;
    if (index === null || !x.length) return hideHover();
    if (!bars && (x[index] < domain[0] || x[index] > domain[1])) return hideHover();
    const format = formatter(options);
    const group = svg.querySelector(".chart-hover");
    if (!group) return;
    group.removeAttribute("hidden");
    const px = sx(x[index]);
    const cross = group.querySelector(".chart-cross");
    cross.setAttribute("x1", px.toFixed(1));
    cross.setAttribute("x2", px.toFixed(1));
    if (bars) cross.setAttribute("class", "chart-cross chart-cross-bar");
    let base = 0;
    const dots = group.querySelectorAll(".chart-dot");
    seriesList.forEach((entry, position) => {
      const value = finite(entry.values[index]) ? Number(entry.values[index]) : null;
      const dot = dots[position];
      if (!dot) return;
      if (value === null) {
        dot.setAttribute("hidden", "");
        return;
      }
      base = stacked ? base + value : value;
      dot.removeAttribute("hidden");
      dot.setAttribute("cx", px.toFixed(1));
      dot.setAttribute("cy", sy(stacked ? base : value).toFixed(1));
    });
    const heading = bars ? (options.categories || [])[index] : timeLabel(x[index], spanOf(domain) > 86400 ? 3 * 86400 : 0, true);
    const lines = seriesList
      .map((entry) => ({ entry, value: finite(entry.values[index]) ? Number(entry.values[index]) : null }))
      .reverse();
    let html = `<div class="chart-tip-head">${esc(heading)}</div>`;
    for (const { entry, value } of lines) {
      html += `<div class="chart-tip-row"><i class="chip ${entry.cls}${entry.dash ? " dashed" : ""}"></i><span>${esc(entry.label)}</span><b>${value === null ? "—" : esc(format(value))}</b></div>`;
    }
    if (stacked && seriesList.length > 1) html += `<div class="chart-tip-row chart-tip-total"><i class="chip"></i><span>${esc(options.totalLabel || "Всего")}</span><b>${esc(format(model.totals[index]))}</b></div>`;
    tip.innerHTML = html;
    tip.hidden = false;
    const tipWidth = tip.offsetWidth || 150;
    const left = px + 14 + tipWidth > width ? px - 14 - tipWidth : px + 14;
    tip.style.left = `${Math.max(4, left)}px`;
    tip.style.top = `${lay.m.top + 4}px`;
    drawLegend(format);
    if (announce) live.textContent = tip.textContent;
  }

  svg.addEventListener("pointermove", (event) => {
    if (!model) return;
    pointerInside = true;
    const box = svg.getBoundingClientRect();
    const position = ((event.clientX - box.left) / (box.width || 1)) * width;
    const index = nearest(position);
    if (index !== hover) showHover(index, false);
  });
  svg.addEventListener("pointerleave", () => {
    pointerInside = false;
    if (document.activeElement === svg) return;
    hover = null;
    hideHover();
    drawLegend(formatter(options));
  });
  svg.addEventListener("focus", () => {
    if (!model?.x.length) return;
    if (hover === null) showHover(model.x.length - 1, true);
  });
  svg.addEventListener("blur", () => {
    if (pointerInside) return;
    hover = null;
    hideHover();
    drawLegend(formatter(options));
  });
  svg.addEventListener("keydown", (event) => {
    if (!model?.x.length) return;
    const last = model.x.length - 1;
    const current = hover ?? last;
    const jump = event.shiftKey ? 10 : 1;
    let next = null;
    if (event.key === "ArrowLeft") next = Math.max(0, current - jump);
    else if (event.key === "ArrowRight") next = Math.min(last, current + jump);
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = last;
    else if (event.key === "Escape") {
      hover = null;
      hideHover();
      drawLegend(formatter(options));
      return;
    } else return;
    event.preventDefault();
    showHover(next, true);
  });

  const stop = watch(container, (nextWidth) => {
    const rounded = Math.round(nextWidth);
    if (rounded > 0 && rounded !== width) {
      width = rounded;
      draw();
    }
  });
  draw();

  return {
    update(next = {}) {
      options = { ...options, ...next };
      draw();
    },
    // The hidden data table is always refreshed on demand (a screen reader asked for it).
    refreshTable() {
      if (model) maybeTable(formatter(options), true);
    },
    destroy() {
      stop();
      root.remove();
    },
  };
}

export function lineChart(container, options) {
  return xyChart(container, "line", options);
}

export function areaChart(container, options) {
  return xyChart(container, "area", options);
}

export function stackedAreaChart(container, options) {
  return xyChart(container, "stacked", options);
}

export function barChart(container, options) {
  return xyChart(container, "bars", options);
}

// -- sparkline ---------------------------------------------------------------------------------

// A tiny, axis-less trend. `series: [{values, cls, dash?, noArea?}]` on a shared `x`.
export function sparkline(container, options) {
  const id = `sp${(uid += 1)}`;
  let opts = { ...options };
  let width = container.clientWidth || options.width || 120;
  const root = make("div", "spark", container);
  const svg = makeSvg("svg", { class: "spark-svg", role: "img" }, root);

  function draw() {
    const height = opts.height || 32;
    const x = opts.x || [];
    const list = (opts.series || []).map((entry, index) => ({ ...entry, cls: seriesClass(entry, index) }));
    const domain = opts.domain || [x[0] ?? 0, x[x.length - 1] ?? 1];
    if (!(domain[1] > domain[0])) domain[1] = domain[0] + 1;
    const pad = 3;
    let top = 0;
    for (const entry of list) for (const value of entry.values) if (finite(value)) top = Math.max(top, Number(value));
    const max = opts.unit === "percent"
      ? (opts.yMax === "auto" ? Math.min(100, Math.max(20, top * 1.3)) : opts.yMax || 100)
      : Math.max(opts.yMax || 0, top * 1.1, opts.unit === "rate" ? BASE : 1);
    const sx = (value) => pad + ((value - domain[0]) / (domain[1] - domain[0])) * (width - 2 * pad);
    const sy = (value) => height - pad - (Math.min(value, max) / max) * (height - 2 * pad);
    const gap = opts.gap ?? defaultGap(x);
    let markup = "<defs>";
    list.forEach((entry, index) => {
      markup += `<linearGradient id="${id}-g${index}" class="${entry.cls}" x1="0" y1="0" x2="0" y2="1"><stop class="gs gs-top" offset="0"/><stop class="gs gs-bottom" offset="1"/></linearGradient>`;
    });
    markup += `</defs><line class="spark-base" x1="${pad}" x2="${width - pad}" y1="${height - pad}" y2="${height - pad}"/>`;
    let endDots = "";
    list.forEach((entry, index) => {
      for (const run of splitSegments(x, entry.values, gap)) {
        const coords = run.map((position) => [sx(x[position]), sy(Number(entry.values[position]))]);
        if (coords.length === 1) continue;
        const line = monotonePath(coords);
        if (!entry.noArea && !entry.dash) markup += `<path class="chart-fill" fill="url(#${id}-g${index})" d="${line}L${coords[coords.length - 1][0].toFixed(1)},${height - pad}L${coords[0][0].toFixed(1)},${height - pad}Z"/>`;
        markup += `<path class="chart-line spark-line ${entry.cls}${entry.dash ? " dash" : ""}" d="${line}"/>`;
      }
      const lastIndex = entry.values.length - 1 - [...entry.values].reverse().findIndex(finite);
      if (lastIndex >= 0 && finite(entry.values[lastIndex]) && x[lastIndex] >= domain[1] - (gap === Infinity ? 1e9 : gap)) {
        endDots += `<circle class="spark-dot ${entry.cls}" cx="${sx(x[lastIndex]).toFixed(1)}" cy="${sy(Number(entry.values[lastIndex])).toFixed(1)}" r="2.4"/>`;
      }
    });
    svg.innerHTML = markup + endDots;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", String(width));
    svg.setAttribute("height", String(height));
    const format = formatter(opts);
    const label = list.map((entry) => {
      const last = [...entry.values].reverse().find(finite);
      return `${entry.label || ""} ${finite(last) ? format(last) : "нет данных"}`.trim();
    }).join(", ");
    svg.setAttribute("aria-label", `${opts.label || "Тренд"}: ${label}`);
  }

  const stop = watch(container, (nextWidth) => {
    const rounded = Math.round(nextWidth);
    if (rounded > 0 && rounded !== width) {
      width = rounded;
      draw();
    }
  });
  draw();
  return {
    update(next = {}) {
      opts = { ...opts, ...next };
      draw();
    },
    destroy() {
      stop();
      root.remove();
    },
  };
}

// -- gauge ring --------------------------------------------------------------------------------

// A ring for one percentage. `pathLength=100` lets the arc be described in percent. The level
// (`warn` ≥ 75, `critical` ≥ 90, like the overview's bars) recolours it and the label says it
// too, so colour is never the only signal.
export function gaugeRing(container, options) {
  let opts = { warn: 75, critical: 90, ...options };
  const root = make("div", "gauge", container);
  const svg = makeSvg("svg", { class: "gauge-svg", viewBox: "0 0 72 72", role: "img" }, root);
  makeSvg("circle", { class: "gauge-track", cx: 36, cy: 36, r: 30, pathLength: 100 }, svg);
  const arc = makeSvg("circle", { class: "gauge-arc", cx: 36, cy: 36, r: 30, pathLength: 100, transform: "rotate(-90 36 36)", "stroke-dasharray": "0 100" }, svg);

  function draw() {
    const value = finite(opts.value) ? Math.max(0, Math.min(100, Number(opts.value))) : null;
    const level = value === null ? "none" : value >= opts.critical ? "critical" : value >= opts.warn ? "warn" : "ok";
    svg.setAttribute("class", `gauge-svg gauge-${level} ${opts.cls || ""}`.trim());
    arc.setAttribute("stroke-dasharray", `${value === null ? 0 : Math.max(value, value > 0 ? 1.2 : 0).toFixed(1)} 100`);
    const state = level === "critical" ? ", критично" : level === "warn" ? ", повышено" : "";
    svg.setAttribute("aria-label", `${opts.label || ""}: ${value === null ? "нет данных" : `${formatPercent(value)}${state}`}`.trim());
  }

  draw();
  return {
    update(next = {}) {
      opts = { ...opts, ...next };
      draw();
    },
    destroy() {
      root.remove();
    },
  };
}
