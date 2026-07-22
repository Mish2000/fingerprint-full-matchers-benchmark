# Running the SourceAFIS frozen-cohort raw-score execution

`sourceafis_frozen_cohort_v1` is the first execution of the qualified SourceAFIS runtime
over the frozen supervisor protocol. It produces raw similarity scores and nothing else:
no threshold is read, no decision field is written, and no accuracy, FMR or FNMR figure is
derived at this stage.

## What the orchestrator guarantees

`tools/run_sourceafis_frozen_cohort_v1.py` refuses to start unless the repository is on a
clean `main`, every frozen tag resolves to its recorded commit, the protocol, qualification
and decision-policy packages match their checksums, and the protected-area tree hashes
still match the ones locked by `policies/sourceafis_decision_policy_v1/policy_lock.json`.
It then verifies the toolchain, builds exactly one shaded JAR, proves the successful path
against the qualification fixture, and only afterwards touches the cohort.

The eight frozen manifests always run in the same order and the tool exposes no way to
select a subset, reorder them, retry individual pairs, or supply a threshold:

1. `sd300b/plain_self.csv`
2. `sd300b/roll_self.csv`
3. `sd300b/plain_roll_genuine.csv`
4. `sd300b/plain_roll_next_subject.csv`
5. `sd300c/plain_self.csv`
6. `sd300c/roll_self.csv`
7. `sd300c/plain_roll_genuine.csv`
8. `sd300c/plain_roll_next_subject.csv`

Each manifest runs in a fresh process and a fresh JVM, contributes 500 result rows, and is
deep-validated row-by-row against its source manifest before the next manifest starts.

## Canonical environment

The series must run in the same conda environment that the runtime qualification used,
identified in every committed artefact as `conda_env/fingerprint-recognition-research`.
The orchestrator asserts Zulu OpenJDK 17.0.18 from Azul Systems, Inc., Maven 3.9.16, an
`amd64` architecture, compiler release 11 and SourceAFIS 3.18.1, and it requires Maven to
report the same Java home as the Java executable it was given.

Point the shell at the environment for the current session only. Never use `setx`, never
change `JAVA_HOME` permanently, and never modify or upgrade the conda environment.

```powershell
$CondaEnv = "$env:USERPROFILE\.conda\envs\fingerprint-recognition-research"
$env:JAVA_HOME = Join-Path $CondaEnv "Library\lib\jvm"
$env:Path = "$CondaEnv\Library\bin;$env:Path"
```

## Running

From the repository root, with the paths for your own machine:

```powershell
& "$CondaEnv\python.exe" tools\run_sourceafis_frozen_cohort_v1.py `
  --repository-root . `
  --dataset-root <dataset-root> `
  --results-root .\results\sourceafis_frozen_cohort_v1 `
  --java "$CondaEnv\Library\bin\java.exe" `
  --maven "$CondaEnv\Library\bin\mvn.cmd"
```

Two narrower modes are available. `--validate-only` re-checks the repository, the frozen
packages, the protected trees and the committed execution package without building or
running anything. `--preflight-only` additionally verifies the toolchain, builds the
canonical JAR and runs the successful-path preflight, then stops before the cohort.

A local `.execution.lock` file inside the results root prevents two concurrent series. It
is removed automatically; delete it by hand only after confirming that no run is active.

## Results, resume and failures

Raw bundles are written under `results/sourceafis_frozen_cohort_v1/raw` and are deliberately
untracked by Git, as is the canonical JAR under `results/sourceafis_frozen_cohort_v1/runtime`.
Only identities, hashes and counts are committed, in `executions/sourceafis_frozen_cohort_v1`.

An existing bundle is reused only when it validates completely and its manifest hash,
protocol lock hash, JAR hash, execution code commit and Java runtime all match the current
series. Anything else is reported as `BLOCKED` and is never overwritten. There is no resume
from the middle of a CSV: an interrupted manifest leaves only a candidate directory, which
is discarded so the whole manifest can run again.

A pair-level extraction or comparison failure is preserved in its own row with an error code
and no score. Failures are never retried selectively and never become a score, a zero, or a
`different` outcome. Every bundle satisfies
`successful_scores + technical_failures = 500`, and a run with technical failures can still
be a valid execution.

## Validating without a dataset

`tools/validate_sourceafis_frozen_cohort_v1.py` is dataset-independent and never starts a
matcher. CI runs it on every push:

```text
python tools/validate_sourceafis_frozen_cohort_v1.py
```

Passing `--results-root` additionally re-validates every local raw bundle against its source
manifest. The validator reads raw scores only far enough to confirm that a successful row
carries a finite, non-negative value; it never returns, prints or aggregates one.

## Stopping point

The execution stage ends with the committed registry. Applying the frozen decision policy,
writing the supervisor report, and computing FMR, FNMR, accuracy, score distributions or
timing comparisons are separate later stages.
