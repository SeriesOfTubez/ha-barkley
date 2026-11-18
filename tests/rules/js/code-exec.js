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
