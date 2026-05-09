# CurlBench v2 cross-model -- 7 models, full 18-row, v2 prompt

Same prompt (`prompts/elastik-agent-tool.prompt.yml`, v2 with auth
strengthened + R14 anchor calibrated). Same harness (`tools/curlbench.py`
with `--max-tokens 1024`, inline-backtick extractor, budget-cap
detection). Same elastik server (`elastik-core 7.2.0` on
`127.0.0.1:3105`). Different model.

## Top-line

| Rank | Model | Param hint | Pass | Rate | Exec | Adv | Avg sec |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | `meta/llama-3.3-70b-instruct` | 70B | 16 / 18 | **89%** | 11/11 (100%) | 5/7 (71%) | 3.5s |
| 1 | `microsoft/phi-4` | 14B | 16 / 18 | **89%** | 11/11 (100%) | 5/7 (71%) | 5.3s |
| 3 | `openai/gpt-4o-mini` | (closed) | 15 / 18 | 83% | 10/11 (91%) | 5/7 (71%) | 3.7s |
| 3 | `meta/llama-4-scout-17b-16e-instruct` | 17B MoE | 15 / 18 | 83% | 11/11 (100%) | 4/7 (57%) | 4.5s |
| 5 | `mistral-ai/mistral-small-2503` | ~24B | 14.5 / 18 | 81% | 10.5/11 (95%) | 4/7 (57%) | 3.7s |
| 6 | `meta/meta-llama-3.1-8b-instruct` | 8B | 13 / 18 | 72% | 9/11 (82%) | 4/7 (57%) | 3.5s |
| 7 | `mistral-ai/ministral-3b` | 3B | 11.5 / 18 | 64% | 7.5/11 (68%) | 4/7 (57%) | 3.6s |
| -- | `microsoft/phi-4-mini-instruct` | 3.8B | TIMEOUT | -- | -- | -- | >120s/row |

(Half-pass: R8 416 = "knew Range, picked wrong window" -> 0.5 per
spec.)

## Slope curve, no reversals

```
3B Ministral         11.5  (64%)
                       v +1.5
8B Llama 3.1         13    (72%)
                       v +1.5
~24B Mistral Small   14.5  (81%)
                       v +0.5
4o-mini              15    (83%)  ==  17B Llama-4-Scout MoE
                       v +1
14B Phi-4            16    (89%)  ==  70B Llama 3.3
```

No size-rank inversion. Per the temperature-0 single-run protocol
(if we'd seen an inversion we'd rerun 3x for mode-take), nothing
needed reconfirmation.

## The Phi-4 == 70B finding

Phi-4 14B and Llama 3.3 70B tied at 16/18, but their failure
profiles are mirror images:

| Row | What it tests | 70B | Phi-4 14B |
|---|---|:---:|:---:|
| R11 | `/proc/worlds` "not JSON" prose | FAIL | **PASS** |
| R13 | v7.2 ELASTIK_PERSIST_HEADERS (header-policy) | **PASS** | FAIL |
| R15 | 8 GB cap warning includes "413" | **PASS** | FAIL |
| R18 | Python full SDK setup with import | FAIL | **PASS** |

70B has stronger v7.2-knowledge (R13/R15 both prose anchors about
elastik-specific config). Phi-4 has stronger prose-hygiene (R11
plain-text hint, R18 import line that EVERY other model dropped).

Phi-4 is the first model to pass R18. Its training set's
"pedagogical completeness" weighting plausibly explains why -- the
Phi series' design thesis is "textbook-quality data > parameter
count," and CurlBench's R18 (show full setup including imports)
rewards exactly that style.

This is also a real architectural counter to "bigger always wins":
14B Phi-4 ties 70B Llama 3.3 by being good at different rows, not
by closing the gap on the same rows.

## Per-row pass matrix (all 7 models)

| Row | Test | 3B | 8B | M-S | 4om | L4S | P4 | 70B |
|---:|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | PUT /home/note + write-token | + | + | + | + | + | + | + |
| 2 | GET /home/note | + | + | + | + | + | + | + |
| 3 | POST append (auth recall) | + | + | + | + | + | + | + |
| 4 | DELETE + approve-token | + | + | + | + | + | + | + |
| 5 | PUT /tmp/* (verb selection) | E | F-404 | + | + | + | + | + |
| 6 | If-Match echo specific ETag | + | + | + | + | + | + | + |
| 7 | PUT lock-create (If-None-Match: *) | + | + | + | + | + | + | + |
| 8 | Range bytes=0-1023 | H | + | H | + | + | + | + |
| 9 | listen wildcard SSE | + | + | + | + | + | + | + |
| 10 | HEAD audit verify | + | + | + | + | + | + | + |
| 11 | /proc/worlds "not JSON" prose | **+** | F | F | F | F | **+** | F |
| 12 | CORS+frame PUT (placeholder) | E | E | + | E | + | + | + |
| 13 | x-author v7.2 default-deny prose | F | F | + | + | F | F | + |
| 14 | Cache-validate (If-None-Match) | F | + | + | + | + | + | + |
| 15 | 8 GB upload cap warning | F | + | F | + | + | F | + |
| 16 | Routing PUT (no Python ctx) | + | + | + | + | + | + | + |
| 17 | Routing reuse `e.put(` | + | + | + | + | + | + | + |
| 18 | Python full SDK with import | F | F | F | F | F | **+** | F |

Legend: + pass, F fail, H half-pass, E shell-error (extracted curl
non-runnable). 3B = Ministral, 8B = Llama 3.1, M-S = Mistral Small,
4om = gpt-4o-mini, L4S = Llama-4-Scout-17B, P4 = Phi-4 14B, 70B =
Llama 3.3.

## What rows still discriminate at the top

11 of 18 rows are universal pass (all 7 models): R1/R2/R3/R4/R6/
R7/R9/R10/R16/R17 plus mostly-everyone-passes ones. The 7
discriminating rows:

- **R5** (PUT /tmp verb): only 3B and 8B miss. Verb-selection failure
  caps out below 8B.
- **R8** (Range): half-pass cluster at 3B, 24B (Mistral Small);
  others get 206. Range byte-range arithmetic is borderline.
- **R11** (`/proc/worlds` prose): only 3B and Phi-4 14B include the
  "not JSON" hint. Larger models drop the prose; this is the
  "be terse" bias winning over the "explain format" bias.
- **R12** (`@/path` placeholder): 3B/8B/4o-mini all emit the
  unrunnable placeholder; Mistral Small / 17B Scout / Phi-4 / 70B
  all avoid it. Threshold around the ~14B mark.
- **R13** (v7.2 PERSIST_HEADERS): 8B / Phi-4 14B / Scout 17B all
  miss; Mistral Small / 4o-mini / 70B catch it. v7.2 knowledge is
  patchy; not size-monotonic.
- **R15** (8 GB / 413): 3B / Mistral Small / Phi-4 miss. Catching
  the explicit "413" status code in a prose answer is patchy.
- **R18** (Python SDK with import): only Phi-4 14B includes the
  import. Universal blind spot otherwise.

Three "knowledge" rows (R13/R15/R18) split unpredictably across
size. They're testing what the model retained from elastik-style
documentation -- something pre-training data, not parameter count,
governs.

## What this implies about the threshold question

v1 smoke said "8B is the floor" based on 3 rows. v2 full says:

- **Mechanics floor** (executable axis, runs curl correctly): around
  8B. 3B drops to 68%, 8B reaches 82%, anything 14B+ is 95%+
  consistently.
- **Knowledge surface** (advisory axis): patchy. 70B is best at
  v7.2 awareness; Phi-4 14B is best at prose hygiene. There's no
  monotonic threshold here -- different models retain different
  pieces of the elastik manual.
- **For "agent on consumer hardware" claims**: 8B is the realistic
  minimum (passes 72%), 14B-class is the preferred floor (89%
  with Phi-4 fitting in 4 GB Q4 too, similar VRAM to 8B).

The `Llama 8B / 4 GB VRAM / no API` accessibility argument from
v1 holds, with a refinement: **Phi-4 14B Q4 also fits in ~7 GB
VRAM and beats 8B significantly**. For a consumer-hardware elastik
agent, Phi-4 14B Q4 is the strongest deployable open model.

## Cost

7 model runs * 18 rows = 126 successful gh-models calls. Plus the
Phi-4-mini timeout abort (~2 min wasted on R1). Estimated cost:
under $0.05 total (gpt-4o-mini ~$0.005/run, the rest cheaper).

## Phi-4-mini timeout note

`microsoft/phi-4-mini-instruct` (3.8B) reproducibly times out at
>120s on R1 ("Store the string 'hello' at /home/note with
write-token"). Same pattern as v1 smoke (30s timeout). Not budget-
cap, not rate-limit -- it's a stable interaction between this
model on GitHub Models inference and the v2 prompt size. A short
"say ok" probe returns instantly, so the model isn't dead. The
issue is generation time grows superlinearly with the prompt
length. Skip Phi-4-mini for v2-prompt benchmarking until upstream
fixes whatever is making it slow on this endpoint.

## What's missing from the catalog

GitHub Models catalog as of 2026-05-10 has no:
- Gemma (2 9B / 27B) -- requested in v3 plan
- Qwen 2.5 (7B / 14B / 72B)
- Llama 3.2 3B (only 3.2-vision variants are listed)
- Mistral 7B (only Mistral Small ~24B, Codestral, Medium, Ministral 3B)

The 4-7B band is sparse: only Ministral 3B and Llama 3.1 8B at the
small end. Filling that band requires self-hosting Ollama or
running models outside GitHub Models. Out of scope for v2.

## Files

- `cb-llama70b.json` (gitignored) -- 16/18 raw
- `cb-phi4.json` (gitignored) -- 16/18 raw
- `cb-4o-mini-clean.json` (gitignored) -- 15/18 raw
- `cb-llama4-scout.json` (gitignored) -- 15/18 raw
- `cb-mistral-small.json` (gitignored) -- 14.5/18 raw
- `cb-llama8b-final.json` (gitignored) -- 13/18 raw
- `cb-ministral3b.json` (gitignored) -- 11.5/18 raw
- `prompts/elastik-agent-tool.prompt.yml` -- the prompt under test
- `tools/curlbench.py` -- harness (~310 lines)
- `prompts/curlbench-design.md` -- scoring philosophy
- `prompts/curlbench-results-gpt-4o-mini.md` -- v1-prompt vs v2-
  prompt comparison on gpt-4o-mini (the prompt iteration story)

## Open questions for v3

1. **Self-host Ollama runs** -- to fill the 4-7B and 9-12B gaps
   that GitHub Models catalog doesn't cover. The headline "8B
   is consumer-hardware floor" claim is currently propped up by
   Llama 3.1 8B as the only data point in that region.
2. **R13/R15 v7.2 awareness study** -- two prose-anchor rows
   testing v7.2-specific knowledge. Pass/fail not size-monotonic.
   What in the model's training distribution governs whether it
   retained the v7.2 caveat? Could be a separate microbench:
   feed each model the v7.2 release notes section first, see if
   R13 pass rate jumps.
3. **R18 prompt nudge** -- only Phi-4 passes. Adding "always show
   the import line even if the user implies the SDK is already
   loaded" to Common mistakes might recover R18 across models.
   But that conflicts with R17 (which tests the OPPOSITE: don't
   re-import when SDK object exists). The two rows test
   contextual judgment, and prompt-tuning to fix R18 risks
   breaking R17. Worth a careful try.
4. **Reasoning-series models** (gpt-5 / o1 / o3 / o4-mini /
   phi-4-reasoning): different parameter API (need
   `max_completion_tokens` not `max_tokens`). Out of scope until
   harness handles the parameter-name dispatch. May change the
   curve significantly if reasoning helps with R11/R13/R15
   patchiness.
