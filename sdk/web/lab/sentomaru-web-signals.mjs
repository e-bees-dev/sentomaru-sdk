// Sentomaru web channel, page side, LABORATORY ONLY (docs/web/W20_BOT_COLLECTOR_DESIGN.md, W-20): reads a closed list of local browser conditions (S1 to S4 of
// docs/web/W19_BOT_SIGNALS_DESIGN.md) and returns booleans in the object `sentomaru-web-signals/1`. It decides nothing: every value is declared by the page's own code and
// can be changed by whoever controls the client, and a missing value is never "human". It is NOT part of the npm package, has no SRI entry and must not run on real
// visitor traffic until the W-22 bench has measured the false-positive rate (decision of 12/11/2026 on D-PR1/D-PR2).
//
// Rules this file keeps (and sentomaru-web-signals.test.mjs proves): off unless `enabled === true` (nothing is read otherwise); reads only the properties named below;
// passive reads only; no storage, no network, no timer, no element, no dynamic code; a condition that cannot be read is `null`, never `false`.

export const SCHEMA = 'sentomaru-web-signals/1';
export const COLLECTOR_VERSION = '0.1.0';

// Names of the browser's global automation artifacts, checked with the `in` operator (a passive presence check: no getter runs). The list is an initial,
// UNMEASURED choice; the W-22 bench decides what stays.
export const AUTOMATION_GLOBALS = Object.freeze([
  'cdc_adoQpoasnfa76pfcZLmcfl_Array', 'cdc_adoQpoasnfa76pfcZLmcfl_Promise', 'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
  '__pwInitScripts', '__playwright__binding__', 'domAutomation', 'domAutomationController', '_phantom', 'callPhantom', '__nightmare',
]);

const read = fn => { try { return fn(); } catch { return undefined; } };
const isString = value => typeof value === 'string';

/** S1: the automation flag the browser itself exposes. */
function s1(navigator) {
  const flag = read(() => navigator?.webdriver);
  return typeof flag === 'boolean' ? flag : null;
}

/** S2: three local conditions of a headless build. true if any holds, false if at least one was readable and none holds, null if none was readable. */
function s2(navigator, scope) {
  const results = [];
  const userAgent = read(() => navigator?.userAgent);
  if (isString(userAgent)) results.push(userAgent.includes('HeadlessChrome'));
  const languages = read(() => navigator?.languages);
  if (Array.isArray(languages)) results.push(languages.length === 0);
  const width = read(() => scope?.outerWidth), height = read(() => scope?.outerHeight);
  if (typeof width === 'number' && typeof height === 'number') results.push(width === 0 && height === 0);
  return results.length === 0 ? null : results.some(Boolean);
}

/** S3: presence of a known automation artifact among the global names listed above. true if any is present; false if the global scope was readable and none is; null otherwise. */
function s3(scope) {
  if (scope === null || (typeof scope !== 'object' && typeof scope !== 'function')) return null;
  let checked = 0;
  for (const name of AUTOMATION_GLOBALS) {
    const present = read(() => name in scope);
    if (typeof present !== 'boolean') continue;
    checked += 1;
    if (present) return true;
  }
  return checked === 0 ? null : false;
}

/** S4: incoherence between the declared agent and other local values, from a closed list of pairs. null when no pair applies to this agent. */
function s4(navigator) {
  const userAgent = read(() => navigator?.userAgent);
  if (!isString(userAgent)) return null;
  const platform = read(() => navigator?.platform);
  const touchPoints = read(() => navigator?.maxTouchPoints);
  const verdicts = [];
  if (userAgent.includes('Windows') && isString(platform)) verdicts.push(!platform.startsWith('Win'));
  if (userAgent.includes('Macintosh') && isString(platform)) verdicts.push(!platform.startsWith('Mac'));
  if (/Mobi|Android|iPhone/.test(userAgent) && typeof touchPoints === 'number') verdicts.push(touchPoints === 0);
  return verdicts.length === 0 ? null : verdicts.some(Boolean);
}

/**
 * The result object, or null when the collector is off. `enabled` must be exactly `true` (the consumer turns it on by its own configuration); nothing is read otherwise.
 * `scope` defaults to the page's global object and exists so the laboratory can hand in a controlled one.
 */
export function collectSignals({ enabled = false, scope = globalThis } = {}) {
  if (enabled !== true) return null;
  const navigator = read(() => scope?.navigator);
  return {
    schema: SCHEMA,
    collector: COLLECTOR_VERSION,
    signals: { s1: s1(navigator), s2: s2(navigator, scope), s3: s3(scope), s4: s4(navigator) },
  };
}
