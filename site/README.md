# Site

A static site with an in-browser demo of the scanner. There is no server-side
code: the demo runs the same Python package as the command line, executed in
the visitor's browser by [Pyodide](https://pyodide.org). Nothing pasted into the
page is sent anywhere, and the page's Content Security Policy forbids
connections to any other site.

## Build and test

```bash
uv run python site/build.py
```

The build writes `site/dist/` (about 15 MB). It downloads Pyodide at a pinned
version, verifies it by SHA-256, and copies it into the site, so that pages
load nothing from a third party. Figures in the measurements section are read
from `benchmark/results/`, and the two examples from `examples/`.

```bash
cd site && npm ci && npx playwright install chromium
```

```bash
node site/smoke.mjs
```

The smoke test serves `site/dist`, runs the demo in a real browser in both
languages, and fails on a console error, on any request that leaves the site,
and on markup from scanned text reaching the page.

## Files

| File | Purpose |
|---|---|
| `content.py` | Page text in English and Russian |
| `src/template.html` | Page layout |
| `src/styles.css`, `src/app.js` | Styling and the demo |
| `htaccess` | Apache settings and security headers, deployed as `.htaccess` |
| `build.py` | Builder |
| `smoke.mjs` | End-to-end test |

## Deployment

`.github/workflows/deploy-site.yml` builds, tests and copies the site over SSH
on every push to `main` that touches it. Until the secrets below exist it
builds and tests only.

| Repository secret | Value |
|---|---|
| `DEPLOY_SSH_HOST` | Host name of the web server |
| `DEPLOY_SSH_PORT` | SSH port; optional, 22 if absent |
| `DEPLOY_SSH_USER` | SSH user name |
| `DEPLOY_SSH_KEY` | Private key of a key pair made for this purpose only |
| `DEPLOY_SSH_KNOWN_HOSTS` | Output of `ssh-keyscan -p PORT HOST`, checked against the host's real fingerprint |
| `DEPLOY_PATH` | Absolute path of the site's directory on the server; must contain `foretaster` |

The copy uses `rsync --delete`, which removes anything else in the target
directory. `DEPLOY_PATH` must therefore be a directory used for this site and
nothing else, and the workflow refuses a path that does not contain
`foretaster`.
