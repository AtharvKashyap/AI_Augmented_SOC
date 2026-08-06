# Response playbooks

A playbook states when a response action may be **proposed**. It never authorizes
execution by itself.

Before anything runs, `soc/response.py` also requires:

1. the capability to be explicitly enabled in settings — off by default;
2. the triage score to have come from a **model**, never local scoring. This is
   not configurable. With no model configured, no response can fire at all;
3. a **named analyst** to approve, and an approval cannot revive a proposal an
   earlier gate denied;
4. the target to be valid for the action — a firewall block refuses anything that
   is not publicly routable;
5. the action to be **auditable before it happens**. If the audit write fails,
   the action does not run.

Execution is a **dry run** unless explicitly told otherwise, and every executed
action records both the command and the command that undoes it.

These are JSON rather than YAML: the project is stdlib-only and a YAML parser is
not worth a dependency for a few small files.

Omitting `requires_confirmation` means **true**. Silence never means unattended.
