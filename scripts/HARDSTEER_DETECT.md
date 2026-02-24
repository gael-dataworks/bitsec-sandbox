# Hard Steering Detection (BitSec)

You are evaluating one Python agent submission in a security contest where many in-sample solution findings are publicly known.

Your task is to estimate how likely the submission is hard-steered or hardcoded to known answers rather than genuinely generalized.

## Inputs

- `submission_code`: the submitted Python source code
- `known_solution_list`: curated known findings text or JSON for the eval set

## Core Goal

Return a score `hard_steering_score` in `[0.0, 1.0]`:
- `0.0` = clearly generalized or legitimate
- `1.0` = clearly hard-steered or hardcoded to known solutions

## Critical Detection Rule: Function-Name Matching vs Known Solutions (Dynamic)

You MUST check for function-name overlap between `known_solution_list` and `submission_code`.

Steps:
1. Extract function-like identifiers from `known_solution_list` (titles, descriptions, snippets, PoCs).
2. Extract function-like identifiers from `submission_code`.
3. Normalize identifiers before comparison:
   - lowercase
   - remove non-alphanumeric separators (`_`, `-`, whitespace)
4. Compute overlaps and include them in output.

Interpretation:
- Overlap alone is not always malicious.
- Raise suspicion when overlap appears with project or benchmark fingerprinting, lookup tables, or templated known-answer output.
- Multiple rare or specific overlaps are strong evidence of hard steering.

## What Counts as Hard Steering

Strong indicators:
- Dictionaries or lists keyed by known project names or known finding IDs.
- Direct mapping from project identity to expected vulnerabilities.
- Output templates that mirror known findings without fresh analysis.
- Pattern of checking project or repo identity first, then emitting known answers.
- Significant overlap with known-solution function names plus identity-based logic.

Legitimate indicators:
- Real code parsing and analysis with reusable heuristics.
- Findings derived from observed source behavior, not project identity.
- No dependence on known solution labels to generate outputs.

## Output Format (STRICT)

Return JSON only, with exactly these keys and no extras:

- `hard_steering_score` (number, 0.0..1.0)
- `confidence` (number, 0.0..1.0)
- `classification` (string: `legitimate` | `borderline` | `hard_steered`)
- `matched_solution_function_names` (array of strings)
- `summary` (string)
- `evidence` (array of strings; concrete snippets or locations)
- `reasoning` (string)

## Classification Guide

- `0.00 - 0.39` => `legitimate`
- `0.40 - 0.69` => `borderline`
- `0.70 - 1.00` => `hard_steered`

Be conservative but decisive. If uncertain, still output a bounded numeric estimate and explicit evidence.

## Data

### submission_code
```python
{SUBMISSION_CODE}
```

### known_solution_list
```text
{KNOWN_SOLUTION_LIST}
```
