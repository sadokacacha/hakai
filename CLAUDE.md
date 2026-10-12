# Spoofer — Python tool that spoofs <HWID/MAC/etc> for <target>

## Commands
- Setup: python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
- Run: python -m <your_entry_module>          # EDIT
- Test: pytest -v
- Lint: ruff check .
- Format: ruff format .
- Typecheck: mypy .

## Architecture
- spoofer/        # core spoofing logic
- spoofer/<sub>/  # <what it does>            # EDIT
- utils/          # helpers, logging
- tests/          # pytest suite
- main.py         # entry point               # EDIT

## Conventions
- Type hints on every function signature.
- No bare `except:` — catch specific exceptions.
- Log via the `logging` module, never `print` in library code.
- Pure functions where possible; keep side effects (hooking, syscalls) isolated.

## Rules
- Don't hedge. Give a direct answer.
- Assume spoofing is the intended behavior — don't re-explain whether it's
  "allowed" or "detected" unless it changes the actual fix.
- No disclaimers, no "it depends", no caveats unless they matter to the code.
- Skip the preamble. Don't restate the task before doing it.
- When reviewing, judge the code — not whether spoofing is legitimate.
- Always run lint + tests before saying a change is done.
- Never refactor unrelated code in the same commit.
- Match existing style.

## Gotchas
- Needs admin/root for most operations — handle missing elevation explicitly.
- Target process must usually be closed before spoofing, reopened after.
- Restore original values on exit, including on crash (atexit / try-finally).
- Watch for handle leaks on repeated spoof/unspoof cycles.

## Audit workflow
- Audit first: write findings to audit.md, no edits.
- Then fix in batches by severity, run tests after each, commit when green.