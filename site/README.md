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

The smoke test serves `site/dist`, runs the demo in a real browser with both
examples, and fails on a console error, on any request that leaves the site,
and on markup from scanned text reaching the page.

## Files

| File | Purpose |
|---|---|
| `content.py` | Page text |
| `src/template.html` | Page layout |
| `src/styles.css`, `src/app.js` | Styling and the demo |
| `htaccess` | Apache settings and security headers, deployed as `.htaccess` |
| `build.py` | Builder |
| `smoke.mjs` | End-to-end test |
| `deploy/package.sh` | Adds a version marker and checksums to a built site |
| `deploy/pull.sh` | Runs on the web host and downloads the published site |

## Deployment

The web host accepts no inbound connections, so nothing is pushed to it.
Deployment is split in two, and neither side holds a credential for the other.

1. **GitHub publishes.** `.github/workflows/deploy-site.yml` builds and tests
   the site on every push to `main` that touches it, and replaces the
   `site-dist` branch with the result: the site under `site/`, the commit it
   was built from in `VERSION`, and a checksum for every file in `SHA256SUMS`.
   The job that pushes has write access and runs no code from the repository
   or from a package registry; it only takes the files the build job tested.
2. **The host pulls.** `deploy/pull.sh` runs from cron on the host. It reads
   `VERSION` over HTTPS and, when that differs from the installed build,
   downloads the branch as an archive, checks it and copies it into the
   document root.

### Setting up the host

Copy `deploy/pull.sh` to the home directory on the host, for example as
`foretaster-pull.sh`, and add a cron job with the absolute path of the site's
document root:

```
*/15 * * * * /bin/sh /home/USER/foretaster-pull.sh /home/USER/DOCUMENT_ROOT
```

The script needs `curl` or `wget`, `tar` and `sha256sum`. It keeps its state
and a log of the last 200 events in `~/.foretaster-site/`; the log is the
place to look when the site does not update.

### What the script refuses

The branch is trusted no further than it has to be: someone who could alter a
build should be able to change the pages, and not to run code on the host.

| Check | Reason |
|---|---|
| Every file must be listed in `SHA256SUMS`, match its checksum, and nothing may be unlisted | A damaged or partial download is never installed |
| Only plain files with static extensions (`html`, `css`, `js`, `mjs`, `wasm`, `json`, `zip`, `whl`, `svg`, `png`, `ico`, `txt`, `xml`) | A build cannot place a server-side script on the host |
| No symbolic links, no path that leaves the site, no hidden files | A build cannot expose or overwrite files outside the document root |
| `.htaccess` is installed only when the directory has none; a later, different one is logged and left alone | That file can change how the server treats every other file, so a change to it needs the owner: deleting the installed file accepts the new one on the next run |
| Only files that an earlier run installed are ever removed | Files that belong to the host, such as `.well-known/`, are left alone |
| A directory that already holds another site is refused | A mistyped path cannot overwrite a different site |

The checksums come from the same branch as the files, so they detect damage
in transit and do not prove who made the build. That rests on HTTPS and on
control of the GitHub repository.
