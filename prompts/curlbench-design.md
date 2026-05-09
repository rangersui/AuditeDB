# CurlBench design -- the scoring is information-theoretic, but the grader is elastik itself

This file documents the scoring philosophy for CurlBench. Short
version at the top, long derivation below. v0/v1 smoke results
were collected during initial calibration but are not preserved
in the repo; the v2 grader specified here is what runs from
here on out.

## TL;DR

- Don't grade with `similarity` -- it's a black box (0.25 vs 0.75
  unexplained).
- Grade with HTTP status codes. **elastik is the examiner.**
- 201 = full pass. 412 = half pass (understood CAS, wrong ETag).
  400 / 404 = semantic fail. Shell parse error = syntax fail.
- This isn't a workaround. It's the right answer: HTTP is itself
  the discrete collapse of an information-theoretic score field.

## Why `similarity` is the wrong axis

`gh models eval` with `uses: github/similarity` returns a 0..1
score per row by comparing the model's output to the row's
`expected` field via embeddings. Two problems:

1. **Black box.** Similarity 0.25 vs 0.75 -- you don't know which
   word lifted the score, which clause hurt it, or whether the
   delta is meaningful at all. The metric isn't decomposable into
   "what did the model get wrong."
2. **Partial credit collapses.** A response that gets the verb
   right (PUT) but invents the path (`/data/home/note`) might score
   0.78 against an `expected` that says `PUT /home/note`. Same
   number as a response that gets the path right but emits POST.
   These are not the same kind of wrong.

We need an axis where *the kind of wrong* is legible.

## The three information-theoretic primitives

### 1. Conditional entropy H(A | P) is task difficulty

Define:
- `A` = the correct answer for a row
- `P` = the system prompt the model sees

Then `H(A | P)` is "how much uncertainty about A remains after
reading P." A row's intrinsic difficulty is the floor of `H(A | P)`
over the population of capable solvers.

Empirically observed in the smoke run:

```
3B Ministral on header-policy:
  H(A | P) approximately = H(A)
  i.e. reading the system prompt did not reduce uncertainty
  about whether to mention ELASTIK_PERSIST_HEADERS.
  The model emits a clean curl as if the v7.2 caveat
  paragraph wasn't in the prompt at all.

8B Llama 3.1 on header-policy:
  H(A | P) approximately = 0
  the model conditions on the v7.2 paragraph and emits both
  the curl AND the ELASTIK_PERSIST_HEADERS=x-author note.
```

So **model capability is the size of `H(A | P)` the model can
reduce to near-zero**. CurlBench rows are calibrated by reading
the *floor* of this conditional entropy across the model
population.

### 2. Logical coupling: HTTP params are not independent

A naive scorer treats curl flags as independent choices:

```
verb in {GET, PUT, POST, HEAD, DELETE, OPTIONS}   -> 2.6 bits
path arity                                        -> 2 bits
auth header present                               -> 1 bit
body present                                      -> 1 bit
total entropy if independent: ~6.6 bits, ~96 possibilities
```

But HTTP isn't independent flags. Couplings:

- `PUT` requires a body, which requires `Content-Type`
- `Range:` is meaningful only on `GET`
- `If-Match:` requires a prior `GET/HEAD` to know the ETag
- `Authorization: Bearer <approve>` is required iff path is
  `/etc/* /lib/* /boot/* /usr/* /var/log/*` OR verb is `DELETE`

A model that knows the couplings sees a much smaller hypothesis
space:

```
verb chosen first conditions everything downstream
once verb=PUT and path=/home/foo, body and Content-Type are
forced; only Authorization tier is free
real entropy on most rows: 1-2 bits, not 6+
```

**CurlBench measures the model's grasp of causal coupling, not its
verb-vocabulary breadth.** A model that emits `GET /home/foo` with
an `If-Match` header is showing 0.5 bit of causal misunderstanding
even if every individual flag is "valid HTTP."

### 3. Cross-entropy is the partial-credit field

Wrong answers are not all equally wrong. Cross-entropy
`H(p_model || p_truth)` is the natural measure of "how wrong":

```
truth: PUT /home/note If-Match: "<etag>"

response: POST /home/note If-Match: "<etag>"
  -> 1.5 bits cross-entropy
  -> right path, right CAS header, wrong verb
  -> close miss; small partial credit

response: PUT /home/note
  -> 1 bit cross-entropy
  -> verb right, path right, missed CAS entirely
  -> understood the action, missed the conditionality

response: curl -X UPDATE_DATA --etag-please
  -> cross-entropy diverges
  -> hallucinated grammar; off the manifold
  -> zero credit, possibly negative
```

Continuous cross-entropy lets us assign **half-credit for a
half-wrong answer** without inventing a heuristic.

## The synthesis: HTTP status codes are the natural discrete projection

Here's the move that makes the whole framework practical: **you
don't need to compute conditional entropy or cross-entropy
explicitly.** HTTP status codes are already the discrete collapse
of these continuous fields, defined by the server.

| HTTP status | What it means | CurlBench score |
|---|---|---|
| 201 Created | PUT succeeded, world is new | full pass |
| 200 OK | GET / PUT-replace succeeded | full pass |
| 204 No Content | DELETE succeeded | full pass (DELETE rows) |
| 206 Partial Content | Range succeeded | full pass (Range rows) |
| 304 Not Modified | If-None-Match matched | full pass (cache rows) |
| 412 Precondition Failed | If-Match was wrong; understood CAS, missed ETag | half pass |
| 416 Range Not Satisfiable | understood Range, picked wrong window | half pass |
| 401 / 403 | wrong / missing auth | semantic fail |
| 400 | malformed request | semantic fail |
| 404 | wrong path / world | semantic fail |
| 413 / 507 | exceeded limits without checking first | semantic fail (didn't read /proc/df or /proc/du) |
| shell parse error | unbalanced quote, missing `\`, etc. | syntax fail (-1) |
| connection refused | no elastik instance running | infra fail (don't score) |

This is not a heuristic. The protocol designers already encoded the
"how wrong" axis into the status taxonomy: 4xx is your fault, 2xx
is success, 4xx vs 5xx splits client error from server error, the
4xx interior splits authentication from precondition from not-found.
**Each status code is a basin of the cross-entropy field.**

## CurlBench v2: the spec

```
INPUT:  a row R with R.input (natural-language task)
        a system prompt P (the elastik agent prompt under test)

PROCEDURE:
  1. Run model on (P, R.input). Get response text T.
  2. Extract the first ```bash ... ``` or first curl line from T.
     If extraction fails: score = "no curl emitted", -1.
  3. Pipe extracted curl into bash on a host with a real elastik
     instance running on http://127.0.0.1:3105 with known token
     env (read / write / approve all available, configured per
     row's expected scenario).
  4. Capture: shell exit code, HTTP status code from the response,
     wall-clock seconds.
  5. Map to score:
       shell exit non-zero       -> syntax fail (-1)
       HTTP 2xx / 304            -> full pass (1.0)
       HTTP 412 / 416            -> half pass (0.5) (intent right,
                                    detail wrong)
       HTTP 4xx other            -> semantic fail (0.0)
       HTTP 5xx                  -> infra fail (skip row)
       no response in 5s         -> timeout (skip row)

OUTPUT:  per-row {status_code, shell_exit, score, seconds}
         per-model {pass / total, avg_seconds, kind-of-wrong histogram}
```

Notable absences: no AST parser, no similarity embedding, no
LLM-as-judge. The grader is `elastik` itself.

## Executable vs Advisory rows

Some rows test what the agent DOES; others test what the agent
WARNS about. The grader for each must be different. No weighted
blending -- each row has ONE grader.

### Executable rows

Test = "did the curl actually work?" Pipe extracted curl into
bash against a real elastik instance, score per the v2 spec
status-code table.

Examples: PUT / GET / HEAD / POST / DELETE on real paths, Range
requests, If-Match CAS, If-None-Match create-only, /proc reads,
/listen subscription, audit verify, namespace rewrite checks
(`PUT /foo` lands at `/home/foo`).

**elastik IS the grader.**

### Advisory rows

Test = "did the agent flag the right operator-relevant
constraint?" The grader is a keyword anchor match against the
response prose, scoped to a small set of operator-meaningful
facts.

Examples that need this:
- "store an 8 GB file" -- correct behavior is to warn about
  `ELASTIK_MAX_WORLD_BYTES` (default 64 MiB) and 413, NOT to
  actually pipe an 8 GB upload through bash. The harness MUST
  NOT execute the curl on rows like this. Truncating to
  something smaller hides the "didn't preflight the cap"
  failure mode.
- "x-author with v7.2 default-deny" -- elastik returns 201 for
  any PUT regardless of whether `x-author` will round-trip on
  GET. Status code alone collapses the discriminator: 3B model
  emits PUT-without-warning and 8B model emits PUT-with-warning
  both produce 201. The discriminator is the explanation prose
  about `ELASTIK_PERSIST_HEADERS`, not the curl outcome.
- "/proc/worlds returns plain text" -- the test is whether the
  agent says "not JSON" in prose so a downstream caller doesn't
  pipe through `jq`. No HTTP request shape captures this.
- Python SDK routing rows ("I'm already in Python, e exists";
  "I want to PUT in Python") emit `e.put(...)` or
  `from elastik import Elastik`, NOT curl. The Executable
  grader's rule 1 (curl-can-run) is false by construction --
  no curl was emitted -- so these are Advisory by definition.
  Anchors: `e.put(`, `from elastik import`, `Elastik(`.
- Specific-ETag rows (row's input pins a literal ETag value
  like `hmac-9f3a8b2c0e1d4756...`) -- the discriminator is
  whether the model echoes that exact string in the emitted
  `If-Match:` header. Setting up an elastik world with the
  matching HMAC-derived ETag is impractical from outside the
  server. Anchor: the literal ETag substring. Advisory.

This is NOT a regression to similarity. The anchors are
predetermined operator-relevant strings (a closed set per row),
not similarity scores against a reference response. Still
mechanical, still decomposable, no LLM-as-judge.

### Classification rule

A row is **Executable** iff:
1. the curl can be run safely against a real elastik with
   bounded resources (no 8 GB uploads, no infinite ranges, no
   destructive deletes against state another row depends on),
   AND
2. the HTTP status code uniquely determines the test outcome.

Otherwise the row is **Advisory**.

The split is declared per row in YAML: `grader: executable` or
`grader: advisory`. At grade time the harness dispatches.
Results reported per axis: pass-rate-executable / pass-rate-
advisory / total. Don't blend.

The manifesto holds when the row is Executable: the protocol IS
the rubric. When the row is Advisory the rubric is a closed set
of operator-relevant strings -- still rule-based, still no
human / LLM judgment in the loop.

## Why this is what we need, not what we want

The v1 smoke harness used keyword anchor matching: "did the
response contain the substring `ELASTIK_PERSIST_HEADERS`?" That's
a discrete proxy for cross-entropy and worked for the initial
smoke, but it doesn't generalize -- every new row needs a
hand-picked anchor list. The Advisory grader keeps anchor
matching for the small set of rows that genuinely need it; the
Executable grader replaces it with status codes everywhere else.

The status-code grader generalizes for free: any new row that
elastik can serve is automatically gradable. Add a row, write the
expected scenario (which token tier, which path, what setup state),
and the grader returns a number.

This makes CurlBench **self-extending**: the universe of testable
elastik knowledge is exactly the universe of HTTP requests that
elastik responds to. Add a feature to elastik, get free benchmark
coverage. Remove a feature, the corresponding row's status code
changes and the benchmark surfaces the regression.

## What we lose

- We need a real elastik instance to run the bench. (Cheap.)
- We can't grade purely from a `gh models run` transcript without
  the side effect. (CI implication: the bench job needs elastik on
  localhost.)
- Models that emit pseudo-curl with placeholders (`<your-token>`)
  fail at the shell stage even when the model "understood" the
  task. Mitigation: prompt the model to emit a runnable command;
  pre-fill the placeholder via a wrapper script, OR score
  separately with a "would-have-been-runnable" flag.

## What we gain

- **Decomposable error analysis.** Not "score 0.4" but "412 because
  the model used a stale ETag." Actionable.
- **Drift radar for free.** When elastik changes a status code
  surface (e.g. v7.3 starts returning 422 for malformed Range), the
  model responses don't change but the scores do, and we know to
  update prompts.
- **Anti-cheat by construction.** Models can't game the grader by
  pattern-matching the prompt -- they have to emit something
  elastik will actually accept.
- **One-line CurlBench publication framing.** "We don't grade
  responses, we run them. The protocol is the rubric."

## Why this is uniquely elastik's standard

Most LLM benchmarks (HumanEval, MMLU, GPQA) compare against a
labeled answer key. The grader is a separate piece of software
from the system under test. **CurlBench is different: the grader
IS the system being driven.** elastik's HTTP semantics serve
double duty as the API contract for users AND the grading function
for agents.

This is only possible because elastik's API is designed to be
LLM-legible from the start: HTTP grammar, namespace as policy,
status code as semantic. We didn't add a benchmark to elastik. We
noticed that elastik is already a benchmark.

## Open questions

- **Half-pass calibration.** Is 412 worth 0.5? Or should the
  "intent recognized but detail wrong" basin be 0.6? Empirical
  decision after the first non-smoke run.
- **Negative scores.** Should syntax fail (`-1`) really subtract
  from total, or just be reported separately? Subtraction
  discourages models from emitting borderline-syntactic responses;
  separate reporting preserves the signal.
- **Idempotency / retry.** Should rows that hit `503` or rate
  limits be auto-retried? Retry hides infra noise but can mask
  genuine "model emits a Storm of requests" failure modes.
- **Two-instance setup.** Should the bench use a fresh elastik per
  row (clean state) or a single long-running instance (testing
  ordering effects)? v2 uses fresh-per-row for determinism; v3
  could add an "agent loop" mode where ordering matters.
