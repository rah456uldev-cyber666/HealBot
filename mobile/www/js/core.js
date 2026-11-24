/* Medibot core: storage, settings, password hashing, accounts, OTP and SMS. */
(function () {
  "use strict";
  var MB = (window.MB = window.MB || {});
  var CFG = window.MB_CONFIG || {};

  // ---------- storage ----------
  function load(key, fallback) {
    try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch (e) { return fallback; }
  }
  function save(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { console.warn("storage full?", e); }
  }
  MB.load = load; MB.save = save;

  // ---------- settings ----------
  var DEFAULT_SETTINGS = {
    mode: "auto",                       // auto = use internet when available, offline = never
    groqKey: CFG.groqApiKey || "",
    groqModel: CFG.groqModel || "",
    ollamaUrl: CFG.ollamaUrl || "",
    ollamaModel: CFG.ollamaModel || "llama3.2:3b",
    fast2smsKey: CFG.fast2smsApiKey || "",
    twilioSid: CFG.twilioAccountSid || "",
    twilioToken: CFG.twilioAuthToken || "",
    twilioFrom: CFG.twilioFromNumber || "",
    emailjsService: CFG.emailjsServiceId || "",     // free OTP by email (emailjs.com)
    emailjsTemplate: CFG.emailjsTemplateId || "",
    emailjsPublicKey: CFG.emailjsPublicKey || "",
    countryCode: CFG.defaultCountryCode || "+91",
    showOtpOnScreen: true,          // demo code on screen when offline / SMS not set up
    demoOnSmsFailure: false,        // if a real SMS fails while online: false = show the error
    theme: "auto"
  };
  MB.settings = function () { return Object.assign({}, DEFAULT_SETTINGS, load("mb_settings", {})); };
  MB.saveSettings = function (s) { save("mb_settings", s); };
  MB.smsConfigured = function () {
    var s = MB.settings();
    return !!(s.fast2smsKey || (s.twilioSid && s.twilioToken && s.twilioFrom));
  };
  MB.emailConfigured = function () {
    var s = MB.settings();
    return !!(s.emailjsService && s.emailjsTemplate && s.emailjsPublicKey);
  };
  /** True when a real OTP (email or SMS) can be sent. */
  MB.otpConfigured = function () { return MB.emailConfigured() || MB.smsConfigured(); };
  MB.validEmail = function (e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(e || "").trim()); };
  MB.maskEmail = function (e) {
    var m = String(e || "").match(/^(.)(.*)(@.*)$/); return m ? m[1] + "*".repeat(Math.min(m[2].length, 6)) + m[3] : e;
  };
  MB.applyTheme = function () {
    var t = MB.settings().theme;
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
    else document.documentElement.removeAttribute("data-theme");
  };
  MB.isOnline = function () { return MB.settings().mode !== "offline" && navigator.onLine !== false; };

  // ---------- helpers ----------
  MB.now = function () { return Date.now(); };
  MB.escape = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };
  MB.nl2br = function (s) { return MB.escape(s).replace(/\n/g, "<br>"); };

  MB.normalizePhone = function (raw) {
    var n = String(raw || "").trim().replace(/[\s\-().]/g, "");
    if (!n) throw new Error("Please enter your mobile number.");
    if (n.indexOf("00") === 0) n = "+" + n.slice(2);
    if (n[0] !== "+") n = MB.settings().countryCode + n.replace(/^0+/, "");
    if (!/^\+[1-9]\d{7,14}$/.test(n)) throw new Error("Please enter a valid mobile number, e.g. 9876543210.");
    return n;
  };
  MB.maskPhone = function (p) { return p.length <= 6 ? p : p.slice(0, 3) + "*".repeat(p.length - 7) + p.slice(-4); };

  MB.passwordProblems = function (pw) {
    var out = [];
    if (pw.length < 8) out.push("at least 8 characters");
    if (!/[A-Za-z]/.test(pw)) out.push("a letter");
    if (!/\d/.test(pw)) out.push("a number");
    return out;
  };

  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function randomHex(bytes) {
    var a = new Uint8Array(bytes); crypto.getRandomValues(a); return hex(a.buffer);
  }
  MB.hashPassword = function (password, saltHex) {
    if (!window.crypto || !crypto.subtle) return Promise.reject(new Error("Secure storage is not available in this browser."));
    var salt = saltHex || randomHex(16);
    var enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"])
      .then(function (key) {
        return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 120000 }, key, 256);
      })
      .then(function (bits) { return { salt: salt, hash: hex(bits) }; });
  };
  MB.sha256 = function (text) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(hex);
  };

  // ---------- accounts (stored on this device) ----------
  MB.users = function () { return load("mb_users", {}); };
  MB.saveUsers = function (u) { save("mb_users", u); };
  MB.currentUser = function () {
    var s = load("mb_session", null) || JSON.parse(sessionStorage.getItem("mb_session") || "null");
    if (!s || (s.expires && s.expires < MB.now())) return null;
    var u = MB.users()[s.phone];
    return u && u.verified ? Object.assign({ phone: s.phone }, u) : null;
  };
  MB.startSession = function (phone, remember) {
    var s = { phone: phone, expires: MB.now() + (remember ? 30 : 1) * 86400000 };
    if (remember) save("mb_session", s); else { localStorage.removeItem("mb_session"); sessionStorage.setItem("mb_session", JSON.stringify(s)); }
  };
  MB.logout = function () { localStorage.removeItem("mb_session"); sessionStorage.removeItem("mb_session"); };

  MB.login = function (phone, password) {
    var users = MB.users(), u = users[phone];
    if (u && u.lockedUntil > MB.now()) {
      return Promise.reject(new Error("Too many failed attempts. Try again in " +
        Math.ceil((u.lockedUntil - MB.now()) / 60000) + " minute(s) or reset your password."));
    }
    if (!u) return Promise.reject(new Error("Incorrect mobile number or password."));
    return MB.hashPassword(password, u.salt).then(function (h) {
      users = MB.users(); u = users[phone];
      if (h.hash !== u.hash) {
        u.fails = (u.fails || 0) + 1;
        if (u.fails >= 5) { u.lockedUntil = MB.now() + 15 * 60000; u.fails = 0; }
        MB.saveUsers(users);
        throw new Error("Incorrect mobile number or password.");
      }
      u.fails = 0; u.lockedUntil = 0; u.lastLogin = MB.now();
      MB.saveUsers(users);
      return u;
    });
  };

  // ---------- OTP ----------
  var OTP_TTL = 5 * 60000, OTP_ATTEMPTS = 5, RESEND_WAIT = 60000;

  MB.pending = function () { return JSON.parse(sessionStorage.getItem("mb_pending") || "null"); };
  MB.setPending = function (p) { if (p) sessionStorage.setItem("mb_pending", JSON.stringify(p)); else sessionStorage.removeItem("mb_pending"); };
  MB.resendWait = function () {
    var p = MB.pending(); return p && p.sentAt ? Math.max(0, Math.ceil((p.sentAt + RESEND_WAIT - MB.now()) / 1000)) : 0;
  };

  function otpMessage(code) {
    return "Your Medibot verification code is " + code + ". It expires in 5 minutes. Do not share it with anyone.";
  }
  function withTimeout(ms) {
    var c = new AbortController(); setTimeout(function () { c.abort(); }, ms); return c.signal;
  }
  function sendFast2Sms(phone, code, key) {
    var body = new URLSearchParams({ route: "q", message: otpMessage(code), language: "english", flash: "0", numbers: phone.slice(3) });
    return fetch("https://www.fast2sms.com/dev/bulkV2", {
      method: "POST", headers: { authorization: key, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(), signal: withTimeout(15000)
    }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) {
      if (!r.ok || !j["return"]) throw new Error("Fast2SMS: " + (j.message || ("error " + r.status)));
    }); });
  }
  // EmailJS sends email straight from the app using only PUBLIC ids (no secret key in the app).
  function sendEmailJs(email, name, code, s) {
    return fetch("https://api.emailjs.com/api/v1.0/email/send", {
      method: "POST", headers: { "Content-Type": "application/json" }, signal: withTimeout(15000),
      body: JSON.stringify({
        service_id: s.emailjsService, template_id: s.emailjsTemplate, user_id: s.emailjsPublicKey,
        template_params: { to_email: email, email: email, to_name: name || "there", name: name || "there", otp: code, passcode: code,
          app_name: "Medibot", message: otpMessage(code), time: new Date(MB.now() + OTP_TTL).toLocaleTimeString() }
      })
    }).then(function (r) { if (!r.ok) return r.text().catch(function () { return ""; }).then(function (t) {
      throw new Error("Email: " + (t || ("error " + r.status)).slice(0, 160));
    }); });
  }
  function sendTwilio(phone, code, s) {
    var body = new URLSearchParams({ To: phone, From: s.twilioFrom, Body: otpMessage(code) });
    return fetch("https://api.twilio.com/2010-04-01/Accounts/" + encodeURIComponent(s.twilioSid) + "/Messages.json", {
      method: "POST",
      headers: { Authorization: "Basic " + btoa(s.twilioSid + ":" + s.twilioToken), "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(), signal: withTimeout(15000)
    }).then(function (r) { if (!r.ok) return r.json().catch(function () { return {}; }).then(function (j) {
      throw new Error("Twilio: " + (j.message || ("error " + r.status)));
    }); });
  }

  /** Send a code. Resolves to {mode: "email"|"sms"|"screen", reason?}. */
  MB.sendOtp = function (phone, purpose, extra) {
    var p = MB.pending();
    if (p && p.phone === phone && p.purpose === purpose && MB.resendWait() > 0) {
      return Promise.reject(new Error("Please wait " + MB.resendWait() + " seconds before requesting another code."));
    }
    var a = new Uint32Array(1); crypto.getRandomValues(a);
    var code = String(a[0] % 1000000).padStart(6, "0");
    var s = MB.settings(), tries = [], errors = [];
    var email = extra && extra.email, via = [];
    if (MB.isOnline()) {
      if (email && MB.emailConfigured()) { tries.push(function () { return sendEmailJs(email, extra.name, code, s); }); via.push("email"); }
      if (s.fast2smsKey && phone.indexOf("+91") === 0) tries.push(function () { return sendFast2Sms(phone, code, s.fast2smsKey); });
      if (s.twilioSid && s.twilioToken && s.twilioFrom && /^\+\d{6,}$/.test(phone)) tries.push(function () { return sendTwilio(phone, code, s); });
      while (via.length < tries.length) via.push("sms");
    }
    function attempt(i) {
      if (i >= tries.length) {
        // Real SMS was possible but every provider failed: report it instead of silently showing a code.
        if (tries.length && !s.demoOnSmsFailure) {
          return Promise.reject(new Error("The code could not be sent: " + errors.join("; ") +
            ". Check the OTP settings, or turn on 'Use demo code if sending fails' in Settings."));
        }
        return Promise.resolve("screen");
      }
      return tries[i]().then(function () { return via[i]; }, function (e) {
        errors.push(e.name === "AbortError" ? "timed out" : e.message); return attempt(i + 1); });
    }
    return attempt(0).then(function (mode) {
      return MB.sha256(phone + "|" + purpose + "|" + code).then(function (h) {
        var pending = Object.assign({}, extra || {}, {
          phone: phone, email: email || null, purpose: purpose, otpHash: h, expires: MB.now() + OTP_TTL, attempts: 0, sentAt: MB.now(), mode: mode,
          shownCode: mode === "screen" && s.showOtpOnScreen ? code : null,
          demoReason: null
        });
        MB.setPending(pending);
        var reason = errors.length ? "sending failed: " + errors.join("; ") :
          !MB.isOnline() ? "you are offline" :
          MB.otpConfigured() ? "no email address or SMS provider for this number" : "real OTP is not set up yet";
        return { mode: mode, reason: mode === "screen" ? reason : null };
      });
    });
  };

  MB.verifyOtp = function (code) {
    var p = MB.pending();
    if (!p) return Promise.reject(new Error("No active code. Please start again."));
    if (p.expires < MB.now()) return Promise.reject(new Error("This code has expired. Please request a new one."));
    if (p.attempts >= OTP_ATTEMPTS) return Promise.reject(new Error("Too many wrong attempts. Please request a new code."));
    return MB.sha256(p.phone + "|" + p.purpose + "|" + String(code || "").trim()).then(function (h) {
      if (h !== p.otpHash) {
        p.attempts += 1; MB.setPending(p);
        var left = OTP_ATTEMPTS - p.attempts;
        throw new Error(left > 0 ? "Incorrect code. " + left + " attempt(s) left." : "Too many wrong attempts. Please request a new code.");
      }
      return p;
    });
  };

  // ---------- patients (the account holder + family members) ----------
  MB.patients = function (user) {
    var self = { id: "self", name: user.name, age: user.age || "", gender: user.gender || "", address: user.address || "", relation: "Self" };
    return [self].concat(load("mb_family_" + user.phone, []));
  };
  MB.saveFamily = function (user, list) { save("mb_family_" + user.phone, list.filter(function (p) { return p.id !== "self"; })); };
  MB.activePatient = function (user) {
    var id = load("mb_active_" + user.phone, "self"), list = MB.patients(user);
    return list.filter(function (p) { return p.id === id; })[0] || list[0];
  };
  MB.setActivePatient = function (user, id) { save("mb_active_" + user.phone, id); };
  MB.updateUser = function (phone, fields) {
    var users = MB.users(); Object.assign(users[phone], fields); MB.saveUsers(users);
  };
  MB.initials = function (name) {
    return String(name || "?").trim().split(/\s+/).slice(0, 2).map(function (w) { return w[0]; }).join("").toUpperCase();
  };
  MB.patientLabel = function (p) {
    return [p.age ? p.age + " yrs" : "", p.gender || ""].filter(Boolean).join(", ");
  };

  // ---------- chat history (per patient, on this device) ----------
  function histKey(phone, pid) { return "mb_chat_" + phone + (pid && pid !== "self" ? "_" + pid : ""); }
  MB.history = function (phone, pid) { return load(histKey(phone, pid), []); };
  MB.saveHistory = function (phone, msgs, pid) { save(histKey(phone, pid), msgs.slice(-200)); };

  // ---------- saved diseases ----------
  MB.saved = function (phone) { return load("mb_saved_" + phone, []); };
  MB.toggleSaved = function (phone, slug) {
    var list = MB.saved(phone), i = list.indexOf(slug);
    if (i >= 0) list.splice(i, 1); else list.unshift(slug);
    save("mb_saved_" + phone, list); return i < 0;
  };
})();
