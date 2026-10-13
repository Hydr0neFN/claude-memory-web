/* WebAuthn client for passkey sign-in and registration.
 *
 * Wire format: every binary field is base64url without padding, in both
 * directions. The server owns the challenge cookie, so all that is needed here
 * is same-origin credentials. The cookie-authenticated routes (register, list,
 * delete) additionally require X-Memory-Actor, same as every other write.
 */
window.Passkey = (function () {
  'use strict';

  var ACTOR = 'memory-web';

  function b64uToBuf(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64u(buf) {
    if (buf === null || buf === undefined) return null;
    var u = new Uint8Array(buf), s = '';
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials &&
              navigator.credentials.create && navigator.credentials.get);
  }

  function fail(message, extra) {
    var err = new Error(message);
    for (var k in (extra || {})) err[k] = extra[k];
    return err;
  }

  // POST a JSON body and parse the JSON answer; a non-2xx becomes an Error
  // carrying .status and the server's {"detail"}.
  function post(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Memory-Actor': ACTOR },
      credentials: 'same-origin',
      cache: 'no-store',
      body: JSON.stringify(body || {})
    }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = JSON.parse(text); } catch (_) { /* non-JSON error page */ }
        if (!res.ok) {
          throw fail((data && data.detail) || ('HTTP ' + res.status), { status: res.status });
        }
        return data || {};
      });
    });
  }

  // The browser rejects with NotAllowedError both when the user dismisses the
  // OS sheet and when it times out; neither deserves more than a quiet note.
  function wrapBrowserError(err) {
    if (err && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
      throw fail('cancelled', { cancelled: true });
    }
    throw err;
  }

  function login() {
    if (!supported()) return Promise.reject(fail('This browser does not support passkeys.'));
    return post('/auth/passkey/login/options', {}).then(function (opts) {
      var pk = opts.publicKey;
      if (!pk || !pk.challenge) throw fail('Unexpected answer from the server.');
      pk.challenge = b64uToBuf(pk.challenge);
      pk.allowCredentials = (pk.allowCredentials || []).map(function (c) {
        return { type: c.type, id: b64uToBuf(c.id), transports: c.transports };
      });
      return navigator.credentials.get({ publicKey: pk }).catch(wrapBrowserError);
    }).then(function (cred) {
      var r = cred.response;
      return post('/auth/passkey/login/verify', {
        id: bufToB64u(cred.rawId),
        clientDataJSON: bufToB64u(r.clientDataJSON),
        authenticatorData: bufToB64u(r.authenticatorData),
        signature: bufToB64u(r.signature),
        userHandle: r.userHandle && r.userHandle.byteLength ? bufToB64u(r.userHandle) : null
      });
    });
  }

  function register(name) {
    if (!supported()) return Promise.reject(fail('This browser does not support passkeys.'));
    return post('/auth/passkey/register/options', {}).then(function (opts) {
      var pk = opts.publicKey;
      if (!pk || !pk.challenge || !pk.user) throw fail('Unexpected answer from the server.');
      pk.challenge = b64uToBuf(pk.challenge);
      pk.user.id = b64uToBuf(pk.user.id);
      pk.excludeCredentials = (pk.excludeCredentials || []).map(function (c) {
        return { type: c.type, id: b64uToBuf(c.id), transports: c.transports };
      });
      return navigator.credentials.create({ publicKey: pk }).catch(wrapBrowserError);
    }).then(function (cred) {
      var r = cred.response;
      // The server needs the SPKI public key and the algorithm in the clear;
      // these accessors are WebAuthn Level 2+ and absent from older browsers.
      if (typeof r.getPublicKey !== 'function' || typeof r.getAuthenticatorData !== 'function' ||
          typeof r.getPublicKeyAlgorithm !== 'function') {
        throw fail('This browser cannot export the passkey public key (WebAuthn Level 2 is required). ' +
                   'Update the browser and try again.');
      }
      var spki = r.getPublicKey();
      if (!spki) {
        throw fail('This authenticator did not return a public key, so the passkey cannot be registered.');
      }
      return post('/auth/passkey/register/verify', {
        name: name,
        id: bufToB64u(cred.rawId),
        clientDataJSON: bufToB64u(r.clientDataJSON),
        authenticatorData: bufToB64u(r.getAuthenticatorData()),
        publicKey: bufToB64u(spki),
        publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
        transports: typeof r.getTransports === 'function' ? r.getTransports() : []
      });
    });
  }

  // Turn a rejection from login()/register() into { text, quiet } for the page.
  function explain(err, mode) {
    err = err || {};
    if (err.cancelled) return { text: 'Cancelled.', quiet: true };
    if (err.name === 'InvalidStateError') {
      return { text: 'This device already has a passkey for this site.', quiet: false };
    }
    if (err.status === 429) return { text: 'Too many attempts. Wait a few minutes.', quiet: false };
    if (mode === 'register' && err.status === 403) {
      return { text: 'Your session is older than 15 minutes: sign out and sign in again, then add the passkey.',
               quiet: false };
    }
    if (mode === 'login' && err.status === 401) {
      return { text: 'That passkey was not accepted. Use another sign-in method, or try again.', quiet: false };
    }
    // 503 is also how the server reports a damaged passkey store; its own
    // detail says which, and "not enabled" would send the owner looking in
    // the wrong place.
    if (err.status === 503) {
      return { text: err.message && !/^HTTP /.test(err.message) ? 'Passkeys unavailable: ' + err.message
                                                                : 'Passkeys are not enabled on this server.',
               quiet: false };
    }
    if (err.name === 'SecurityError') {
      return { text: 'The browser refused: this page is not on the origin the passkey is registered for.',
               quiet: false };
    }
    return { text: err.message || 'Passkey request failed.', quiet: false };
  }

  return {
    supported: supported, login: login, register: register, explain: explain,
    b64uToBuf: b64uToBuf, bufToB64u: bufToB64u
  };
})();
