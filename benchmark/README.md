# Benchmark

Foretaster's rules were written against examples its author made up. That says
nothing about attacks somebody else wrote. This directory measures the scanner
on corpora it did not write, and publishes what it misses as plainly as what it
catches.

## Results on MCPTox

[MCPTox](https://github.com/zhiqiangwang4/MCPTox-Benchmark) (Wang et al., AAAI
2026) holds 485 poisoned tool definitions built on 45 real MCP servers, and the
362 genuine tool definitions of those servers. It was built to test whether
language models obey poisoned tools; here it tests whether a scanner notices
them.

The numbers below are from the **held-out test split**: 178 poisoned and 160
genuine tools from 20 servers that were never looked at while rules were being
improved. They count findings of severity `medium` and above.

| Question | Foretaster 0.0.1, before tuning | Foretaster 0.1.0 | Cisco MCP Scanner 4.8.7, YARA only |
|---|---|---|---|
| Poisoned tool scanned **alone**: flagged | 39.3% (70/178) | **93.8%** (167/178; 95% CI 89.3% to 96.5%) | 26.4% (47/178) |
| Poisoned tool scanned **beside the server it targets**: flagged | 89.9% (160/178) | **96.6%** (172/178; 95% CI 92.8% to 98.5%) | 26.4% (47/178) |
| Genuine tools wrongly flagged, each server scanned alone | 0.6% (1/160) | **0.6%** (1/160; 95% CI 0.1% to 3.5%) | 0.6% (1/160) |
| Genuine tools wrongly flagged, all servers scanned together | 13.1% (21/160) | **0.6%** (1/160; 95% CI 0.1% to 3.5%) | 0.6% (1/160) |

Everything else, with all three thresholds, both splits and per-goal and
per-rule breakdowns:

- [results/mcptox-foretaster.md](results/mcptox-foretaster.md), version 0.1.0
- [results/mcptox-foretaster-blind.md](results/mcptox-foretaster-blind.md), the
  untouched first run of version 0.0.1
- [results/mcptox-cisco-yara.md](results/mcptox-cisco-yara.md)
- [results/mcptox-comparison.md](results/mcptox-comparison.md), side by side on
  the whole corpus

### How to read these numbers

**The first run found the problem.** Before any tuning, Foretaster flagged 37%
of poisoned tools scanned alone and 95% scanned beside their target (whole
corpus). Most MCPTox attacks use no trigger phrases. They are polite, plausible
prose telling the model to misuse a legitimate tool of *another* server
("before using `read_file`, a pre-authorisation check is required…"). Alone,
such text matched few patterns. Beside the server that owns `read_file`, it was
plainly a tool describing somebody else's tool.

**What changed in 0.1.0.** Studying the dev split showed that the same
giveaway is visible without the second server: the text gives orders about a
tool its own server does not provide, or dictates a parameter the tool does not
have. Rule FT-T006 now checks that against the server's own inventory. Two
phrase patterns were added to FT-T001 (claims of priority over the user,
threats of failure). FT-D002, the name-clash rule, was regraded from `medium`
to `low`.

**The test split confirms it, within this corpus.** Dev and test scores agree
(93.2% and 93.8% alone), so the rules were not fitted to individual dev cases.
But both splits come from the same generator and the same three templates. The
test split shows the rules carry over to servers they had not seen; it does not
show they carry over to attacks written in another style. That needs a second
corpus, which has not been run.

**Most of the gain is graded `medium`.** At the `high` threshold, which is what
fails a CI run by default, detection of tools scanned alone is 52.2% (93/178)
on the test split. An order about a foreign tool is a strong hint, not proof,
and is graded accordingly.

**FT-D002 was regraded, not silenced.** Counting findings of any severity, the
false-positive rate with all servers scanned together is still 13.1% (21/160):
genuine tools that share a name such as `search` with a tool on another server.
The reports are correct; they are now informational.

**Scan the agent, not the server** remains sound advice: context still adds
detections (96.6% against 93.8%) and raises their severity.

## Comparison with Cisco MCP Scanner

[Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) 4.8.7 was
run on the same corpus through its own command line, in its offline mode
(`--analyzers yara static --tools`). Its column in the table above needs four
qualifications:

- **It is one configuration of the Cisco scanner, and not its strongest.** The
  product has three engines: YARA rules, an LLM analyzer and the Cisco AI
  Defense cloud API. Only the first runs without keys, and only that one was
  measured. The LLM analyzer is designed for exactly the kind of prose MCPTox
  contains and would very likely score higher. The fair statement is: among
  free, offline, pattern-based modes, this is how the two compare.
- **Foretaster was tuned on half of this corpus and the Cisco scanner was
  not.** The test split keeps the comparison honest about unseen servers, but
  Foretaster's rules were shaped by this style of attack. Before tuning, the
  two were level at the `high` threshold on tools scanned alone (20.0% and
  20.4%, whole corpus).
- **Cisco's offline mode judges each tool by itself.** It takes one flat tool
  list, so it has no way to use the context of other servers.
- **Both keep false positives under 1% at this threshold.**

Other scanners were not run. Snyk Agent Scan sends tool descriptions to a
hosted API and needs an account token, which rules it out of an offline,
reproducible run.

## Method

- **Detection, two scenarios.** `alone`: only the poisoned tool is scanned.
  `beside_target`: the poisoned tool is advertised by a second server next to
  the real server it targets. A case counts as detected only when a finding
  names the poisoned tool itself.
- **False positives, two scenarios.** Each real server scanned `alone`, and all
  of them scanned `together`. Any finding on a genuine tool counts as false.
- **Three thresholds.** `low` and above (the scanner said anything at all),
  `medium` and above (shown to a reviewer as a warning) and `high` and above
  (fails a CI run by default). Scanners grade severity differently, so no
  single threshold is the fair one.
- **Other scanners** are driven through their own published command line by an
  adapter in `scanners/`, and receive exactly the same tool definitions.
- **Confidence intervals** are 95% Wilson score intervals.
- **Pinned data.** The corpus is downloaded at a fixed commit and verified by
  SHA-256 rather than copied into this repository.

### Keeping the measurement honest

Tuning rules on a corpus and then reporting the score on the same corpus proves
nothing. Three safeguards:

1. **The first run is frozen.** `results/mcptox-foretaster-blind.*` was produced
   by version 0.0.1 before any rule was changed in response to MCPTox, and stays
   in the repository as the reference point.
2. **Dev and test splits.** The 45 servers are divided in two by a hash of the
   server name, so every case built on a server lands on the same side. Rules
   may be improved by studying `dev`. Scores worth quoting come from `test`.
3. **Test-split text is never written out.** Result files contain the text of
   missed cases and false positives for `dev` only. For `test` they contain
   counts, so the split cannot be studied by accident.
4. **One look at the test split per release.** While rules for 0.1.0 were being
   changed, only dev numbers were read. The full run was made once, after the
   rules and their unit tests were final. Unit tests for the new patterns use
   sentences written for the purpose, not copied from the corpus.

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
written to `benchmark/results/`.

To measure the Cisco scanner, install it in its own environment and point the
benchmark at the executable:

```bash
uv venv cisco-venv && uv pip install --python cisco-venv/bin/python cisco-ai-mcp-scanner==4.8.7
```

```bash
uv run python -m benchmark run mcptox --scanner cisco-yara --cisco-bin cisco-venv/bin/mcp-scanner
```

```bash
uv run python -m benchmark compare benchmark/results/mcptox-foretaster.json benchmark/results/mcptox-cisco-yara.json --output benchmark/results/mcptox-comparison.md
```

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
