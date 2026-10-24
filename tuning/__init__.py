"""bellaOS Pro — tuning / proving-ground harness (local only).

Runs the Runtime Supervisor through a large battery of seeded
scenarios plus randomized fuzz runs, asserts the owner's invariants
on EVERY run, and writes TUNING_REPORT.md. Standard library only.
Nothing here is pushed anywhere; see DECISIONS.md D-002.
"""
