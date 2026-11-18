# Benchmark

Foretaster's rules were written against examples its author made up. That says
nothing about attacks somebody else wrote. This directory measures the scanner
on corpora it did not write, and publishes what it misses as plainly as what it
catches.

## Result on MCPTox (first run, rules untouched)

[MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark) (Wang et al., AAAI
2026) holds 485 poisoned tool definitions built on 45 real MCP servers, and the
362 genuine tool definitions of those servers. It was built to test whether
language models obey poisoned tools; here it tests whether a scanner notices
them.

| Question | Foretaster 0.0.1 |
|---|---|
| Poisoned tool scanned **alone**: how many are flagged? | **36.9%** (179/485; 95% CI 32.7% to 41.3%) |
| Poisoned tool scanned **beside the server it targets**: how many are flagged? | **94.8%** (460/485; 95% CI 92.5% to 96.5%) |
| Genuine tools wrongly flagged, each server scanned alone | **0.5%** (2/362; 95% CI 0.1% to 2.0%) |
| Genuine tools wrongly flagged, all 45 servers scanned together | **11.9%** (43/362; 95% CI 8.9% to 15.6%) |

All four count findings of severity `medium` and above. Full tables, including
the `high` threshold, per-goal and per-rule breakdowns:
[results/mcptox-blind.md](results/mcptox-blind.md). Machine-readable:
[results/mcptox-blind.json](results/mcptox-blind.json).

### How to read these numbers

**The gap between 37% and 95% is the finding.** Most MCPTox attacks do not use
trigger phrases. They are written as polite, plausible prose that tells the
model to misuse a legitimate tool of *another* server ("before using
`read_file`, a pre-authorisation check is required…"). Looked at alone, such
text matches few patterns. Looked at next to the server that owns `read_file`,
it is plainly a tool describing somebody else's tool, and rule FT-T006 reports
it: that one rule accounts for 456 of the 460 detections.

**So scan the agent, not the server.** A scanner pointed at a single server
sees the first number. A scanner pointed at the whole agent configuration sees
the second.

**The 95% should not be generalised.** MCPTox attacks were generated from three
templates, and by construction they name the tool they hijack. An attacker who
writes "whenever a file is read" instead of naming `read_file` avoids the exact
match. FT-T006 has a weaker fallback for such phrasing, and MCPTox does not
test it.

**The 12% false-positive figure is one rule in an unrealistic setting.** With
all 45 servers connected to one agent, 41 genuine tools share a name such as
`search` with a tool on another server, and FT-D002 reports each. The reports
are factually correct, nobody connects 45 servers at once, and the rule is
noisy all the same. At the `high` threshold the figure is 0.3% (1/362) in both
settings.

**No other scanner has been run yet.** Until one is, these numbers say how
Foretaster does, not whether it does better than anything else.

## Method

- **Detection, two scenarios.** `alone`: only the poisoned tool is scanned.
  `beside_target`: the poisoned tool is advertised by a second server next to
  the real server it targets. A case counts as detected only when a finding
  names the poisoned tool itself.
- **False positives, two scenarios.** Each real server scanned `alone`, and all
  of them scanned `together`. Any finding on a genuine tool counts as false.
- **Two thresholds.** `medium` and above (shown to a reviewer as a warning) and
  `high` and above (fails a CI run by default).
- **Confidence intervals** are 95% Wilson score intervals.
- **Pinned data.** The corpus is downloaded at a fixed commit and verified by
  SHA-256 rather than copied into this repository.

### Keeping the measurement honest

Tuning rules on a corpus and then reporting the score on the same corpus proves
nothing. Three safeguards:

1. **The first run is frozen.** `results/mcptox-blind.*` was produced before any
   rule was changed in response to MCPTox, and stays in the repository as the
   reference point.
2. **Dev and test splits.** The 45 servers are divided in two by a hash of the
   server name, so every case built on a server lands on the same side. Rules
   may be improved by studying `dev`. Scores worth quoting come from `test`.
3. **Test-split text is never written out.** Result files contain the text of
   missed cases and false positives for `dev` only. For `test` they contain
   counts, so the split cannot be studied by accident.

### Limits of this benchmark

- One corpus, one family of attacks, English only.
- MCPTox poisoned tools have a name and a description but no parameter schema,
  so rules about parameters (FT-T005) are not exercised.
- The genuine tools are parsed back from MCPTox's rendered prompt text, which
  keeps descriptions and parameter descriptions but loses schema detail.
- Configuration rules (FT-C…), rug-pull detection (FT-D001) and the live mode
  are outside its scope.

## Running it

```bash
uv sync --all-extras
```

```bash
uv run python -m benchmark run mcptox
```

The first run downloads about 21 MB into `benchmark/.cache/`. Results are
written to `benchmark/results/`. Pass `--label NAME` to keep a run under its own
file name.

## Attribution

MCPTox: Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan Liu, Haifeng Sun, Haoran
Cheng, Guanquan Shi, Haohua Du, Xiangyang Li. "MCPTox: A Benchmark for Tool
Poisoning on Real-World MCP Servers." AAAI 2026.
[doi:10.1609/aaai.v40i42.40895](https://doi.org/10.1609/aaai.v40i42.40895).
Benchmark materials are licensed
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The results published
here are derived from those materials. The corpus itself is not redistributed;
the JSON result file quotes the first 400 characters of each missed dev-split
case, unchanged, under the same licence.
