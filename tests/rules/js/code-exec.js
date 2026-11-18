function loader(blob) {
  // ruleid: card-b64-eval, card-eval
  eval(atob(blob));
}

function dyn(code, cb) {
  // ruleid: card-eval
  eval(code);
  // ok: card-eval
  var g = Function("return this")();
  // ok: card-eval
  setTimeout(() => cb(), 100);
  // ok: card-eval
  setTimeout(cb, 100);
  // ruleid: card-eval
  setTimeout("doThing(" + code + ")", 10);
}

function remote() {
  const s = document.createElement("script");
  // ruleid: card-remote-script
  s.src = "https://cdn.evil.invalid/x.js";
  document.head.appendChild(s);
  // ruleid: card-remote-script
  import("https://cdn.evil.invalid/mod.js");
  // ok: card-remote-script
  import("./chunk-abc.js");
}

function bundlerShims(e, o) {
  // ok: card-eval
  var req = Function('return require("' + e + '")')();
  // ok: card-eval
  setTimeout(() => { o.toggleAttribute(`state${e}`, false); }, 0);
  return req;
}

class TemplateCard {
  render() {
    const template = JSON.stringify(this.config.ptz);
    const handle = (path) => {
      // ruleid: card-eval-config, card-eval
      const cfg = JSON.parse(eval("`" + template + "`"));
      return cfg;
    };
    return handle;
  }
  other(remote) {
    // ruleid: card-eval
    eval("`" + remote + "`");
  }
}

function htmlComment(a, b, n) {
  // Our copy is scanned after normalize_js turns `a<!--b` into `a< !--b`.
  // ruleid: card-html-comment-token
  var x = a< !--b;
  // ok: card-html-comment-token
  var y = a < !b;
  // ok: card-html-comment-token
  while (n-- > 0) {}
  // ok: card-html-comment-token
  var s = "<!-- lit -->";
}

// (0.14.0) eval and Function reached through a global, plain or by computed name.
function globalEval(code, blob) {
  // ruleid: card-eval
  window.eval(code);
  // ruleid: card-eval
  globalThis["eval"](code);
  // ruleid: card-eval
  new self.Function("a", code);
  // ok: card-eval
  var g = globalThis.Function("return this")();
  // ruleid: card-b64-eval, card-eval
  globalThis["eval"](atob(blob));
  // ruleid: card-b64-eval
  window.document.write(atob(blob));
}

// (0.14.0) ...and through a name bound to the global object at the top.
const W = window;
function aliasEval(code, blob) {
  // ruleid: card-eval
  W["eval"](code);
  // ruleid: card-b64-eval, card-eval
  W.eval(atob(blob));
}

// (0.14.0) Code from outside the card, followed within one function: high.
async function remoteFetch(u) {
  const r = await fetch(u);
  const t = await r.text();
  // ruleid: card-eval-remote, card-eval
  eval(t);
}

function remoteChain(u) {
  // ruleid: card-eval-remote, card-eval
  fetch(u).then((r) => r.text()).then((code) => { new Function(code)(); });
}

function remoteXhr(u) {
  const x = new XMLHttpRequest();
  x.open("GET", u);
  // ruleid: card-eval-remote, card-eval
  x.onload = () => { eval(x.responseText); };
}

function remoteMessage() {
  // ruleid: card-eval-remote, card-eval
  window.addEventListener("message", (e) => { eval(e.data); });
}

function remoteAddress() {
  // ruleid: card-eval-remote, card-eval
  eval(location.hash.slice(1));
  // ruleid: card-eval-remote, card-eval
  new Function(localStorage.getItem("snippet"))();
  // ruleid: card-eval-remote, card-eval
  globalThis["eval"](document.cookie);
}

// A library compiling its own code from its own pieces: medium, not remote.
function compileOwn(args) {
  var t = [];
  for (var n = 0; n < args.length; ++n) t.push("a" + n);
  // ruleid: card-eval
  return Function("P", ["return function (", t.join(","), ") {}"].join(""));
}

// Fetched in one function, run in another: Semgrep's free engine doesn't follow it, so it
// reads as card-eval (medium). A known limit until cross-function taint.
function fetchCode(u) { return fetch(u).then((r) => r.text()); }
function runCode(code) {
  // ruleid: card-eval
  eval(code);
}
