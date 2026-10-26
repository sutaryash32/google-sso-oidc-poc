// Small browser stand-in shared by the hub-and-spoke e2e suites: a path-aware cookie jar (several realms on one origin all use
// the cookie name AUTH_SESSION_ID, so a flat per-origin jar would mix them up) and JWT decoding.

export class Jar {
  #c = new Map();
  store(url, res) {
    const u = new URL(url);
    for (const sc of res.headers.getSetCookie()) {
      const parts = sc.split(';').map((s) => s.trim());
      const i = parts[0].indexOf('=');
      const name = parts[0].slice(0, i), value = parts[0].slice(i + 1);
      const path = parts.find((p) => /^path=/i.test(p))?.slice(5) ?? '/';
      const key = `${u.origin}|${path}|${name}`;
      if (/max-age=0|expires=thu, 01 jan 1970/i.test(sc) || value === '') this.#c.delete(key); else this.#c.set(key, value);
    }
  }
  header(url) {
    const u = new URL(url);
    return [...this.#c].filter(([k]) => { const [o, p] = k.split('|'); return o === u.origin && u.pathname.startsWith(p); })
      .map(([k, v]) => `${k.split('|')[2]}=${v}`).join('; ');
  }
}

export const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
