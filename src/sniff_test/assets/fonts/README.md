# Barkley's fonts

Geist (text) and Geist Mono (identifiers: hosts, files, versions, scan ids) are the
panel's typefaces, shared with Constellus. The panel serves them itself at
`<ingress base>/fonts/<file>` (`server.py`), so nothing is fetched from a font CDN: the
panel's Content-Security-Policy stays `default-src 'none'` with only `font-src 'self'`
added. Fonts are data, never code.

| File | Bytes | Source inside the package | SHA-256 |
|---|---|---|---|
| `Geist-Variable.woff2` | 69,488 | `dist/fonts/geist-sans/Geist-Variable.woff2` | `3626eba547294501c8a4d662c7d9ea3b49734409a4c5a1ccf12fa86429b1687e` |
| `GeistMono-Variable.woff2` | 71,212 | `dist/fonts/geist-mono/GeistMono-Variable.woff2` | `5d93ee62680bbec1abc5405c2658311f9396f6f9a821ef8551ec463887e600d4` |

- **Publisher:** Vercel, the type's authors. npm package `geist` v1.9.2, published
  2026-11-06, tarball integrity
  `sha512-UU1x2q5Khob0+i4csFvXk1Ki4DePdu7xISuXyEcj1tzQMg64oN7Kbuy4e5z5QhcUWbbvOMJNs3ZxYQqpsEMV3w==`.
  Upstream repository: `vercel/geist-font`. The two files here are byte-identical to the
  ones vendored in Constellus (`frontend/public/fonts/`, checksums above).
- **Licence:** SIL Open Font License 1.1. `LICENSE-OFL.txt` is the package's `LICENSE.txt`
  verbatim and must stay next to the font files.
- **Why vendored:** two woff2 files are an asset, not a dependency; the `geist` npm package
  is 8 MB of TTF plus Next.js glue, and the Fontsource builds are not by the authors.
- Variable weight axis 100–900. The panel uses 400 / 500 / 600, and 700 for scores.

## Updating

1. In an empty scratch directory outside the repo, run `npm pack geist@<version>` and
   extract the two files above from the tarball.
2. Check the first four bytes of each file are `wOF2`, then record the new version,
   publish date, tarball integrity and SHA-256 values in this table.
3. Copy the files over the ones here. `tests/test_fonts.py` checks that both files exist,
   are woff2, match the names the CSS references, and that no font URL points off-box.
