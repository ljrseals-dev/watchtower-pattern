# Part 4 — Operating the Harness Like You Mean It

The code is the easy part. The program is:

1. **Baseline on a known-good state.**  
   `python harness.py baseline` after a fresh install, after a signed update, after any intentional change. Document the change in the audit log.

2. **Scan on a schedule and on triggers.**  
   Cron the scan; also scan after any update, any new dependency, any permission change, any auth event that smells wrong.

3. **Review daily, not weekly.**  
   The review queue is the product. A finding that sits open for a week is a finding you've decided not to care about. The `--limit` default is 20 because attention is finite.

4. **Record rationale every time.**  
   `cmd_review` forces it. That rationale is what turns a log into an audit trail and an audit trail into a defensible decision.

5. **Measure the false-positive rate.**  
   `python harness.py report` prints dismissed / reviewed. If it's above ~30%, the thresholds or the adapters need tuning — or the harness is telling you something you don't want to hear about your environment.

6. **Verify the chain weekly.**  
   `python harness.py verify`. A broken chain is an incident, not a chore.

7. **Purge on the retention schedule.**  
   `python harness.py purge --days N`. Closed findings only; open findings are never purged.

8. **Review the reviewer.**  
   The audit log records who decided what and why. That's not surveillance of the reviewer — it's the evidence that the human-in-the-loop was real.
