// Where to send someone after they sign in -- and the reason it is an
// allowlist rather than a validator.
//
// THE ATTACK THIS EXISTS TO PREVENT
//
// An open redirect: darweshgroup.com/login.html?next=https://evil.invalid
// is a link that LOOKS like this site, is served by this site, shows
// this site's real login form, and then hands the visitor to somebody
// else -- often a pixel-perfect copy asking them to "log in again". The
// phish borrows this domain's reputation, and every downstream defence
// (CSP, HTTPS, the real Firebase session) is intact and irrelevant.
//
// WHY NOT A VALIDATOR
//
// The tempting fix is to parse the value and reject anything that is
// not same-origin. That is a long history of near-misses: "//evil.invalid"
// (protocol-relative, same-origin by string prefix, not by browser),
// "https:/\evil.invalid", "\\\\evil.invalid", "java\tscript:alert(1)",
// "%2f%2fevil.invalid" decoded once too often, "https://darweshgroup.com@evil.invalid".
// Each of those has broken a real validator somewhere. An allowlist has
// no such surface: a value either IS one of a handful of known strings
// or it is discarded, and no parser is consulted to decide.
//
// So this module never builds a URL out of untrusted input. It compares
// the input against a fixed list of this site's own pages and returns
// either a member of that list or the fallback. Nothing in between.
//
// WHAT COUNTS AS UNTRUSTED
//
// The whole query string. It arrives from wherever the visitor clicked,
// which may be an email, a message, or a search result someone else
// wrote. `next` is a hint, not an instruction.

// Every page a "sign in and come back" flow may return to.
//
// Deliberately a short list of real, existing routes rather than a
// pattern like /^[a-z-]+\.html$/: a pattern admits any page this site
// might ever host, including an upload target, an admin screen, or a
// page that does not exist yet and will be written without this in
// mind. Adding a route here is one line and one decision; the point is
// that it IS a decision.
export const SAFE_NEXT_ROUTES = Object.freeze([
  'sell.html',        // the reason this module exists
  'account.html',
  'buy.html',
  'rent.html',
  'map.html',
  'services.html',
  'projects.html',
  'arena.html',
  'verify.html',
]);

/**
 * The page a `next` value asks for, or null if it asks for anything
 * else at all.
 *
 * Returns null -- never a "best effort" cleanup of the input. A value
 * this does not recognise is not repaired, trimmed into shape, or
 * partially honoured; it is dropped, and the caller falls back to its
 * own default destination.
 *
 * @param {string|null|undefined} value the raw `next` parameter
 * @returns {string|null} a member of SAFE_NEXT_ROUTES, or null
 */
export function safeNextRoute(value) {
  if (typeof value !== 'string') return null;
  // No trimming, no lowercasing, no decoding. URLSearchParams has
  // already performed exactly one percent-decode, which is the correct
  // number; decoding again is how "%252f%252fevil.invalid" becomes
  // "//evil.invalid" after the check has already passed it.
  return SAFE_NEXT_ROUTES.includes(value) ? value : null;
}

/**
 * Reads `next` from a query string and resolves it.
 *
 * @param {string} search e.g. location.search
 * @returns {string|null}
 */
export function readNext(search) {
  let params;
  try {
    params = new URLSearchParams(search || '');
  } catch {
    return null;
  }
  return safeNextRoute(params.get('next'));
}

/**
 * The `?next=...` suffix to hang on a link to login.html or
 * signup.html, so the two pages can hand the visitor back and forth
 * without losing the destination.
 *
 * Built from the RESOLVED route, so an unsafe value cannot survive a
 * round trip through this site's own links.
 *
 * @param {string} search e.g. location.search
 * @returns {string} '' or '?next=<route>'
 */
export function nextQuery(search) {
  const next = readNext(search);
  return next ? `?next=${encodeURIComponent(next)}` : '';
}

/**
 * Where to send a visitor who has just signed in.
 *
 * `fallback` is whatever the page would have done without a `next` --
 * on login.html that is resolveProfileDestination(profile), which
 * routes an office owner, an agent, a professional or an admin to their
 * own dashboard. That behaviour is preserved exactly: `next` only ever
 * overrides it when it names a known route.
 *
 * @param {string} search e.g. location.search
 * @param {string} fallback the page's own default destination
 * @returns {string}
 */
export function destinationAfterAuth(search, fallback) {
  return readNext(search) || fallback;
}
