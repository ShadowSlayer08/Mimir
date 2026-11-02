---
name: Bug report
about: Something inside Mimir broke
title: "[bug] "
labels: ["bug", "triage"]
---

### What happened

<!-- A clear, concrete description of the broken behaviour. -->

### What you expected

<!-- The behaviour you expected instead. -->

### Reproduction steps

1.
2.
3.

### Environment

- Mimir version (`python -c "import mimir_app; print(mimir_app.__version__)"` or git short-sha):
- Python version (`python --version`):
- Operating system:
- Running headless (CLI) or via `mimir-ops` web app:
- Local Ollama in use? If yes, which model (`llm.pick('planner')`):

### Logs / traceback

```
<paste the full traceback or relevant log excerpt here>
```

### Scope confirmation

- [ ] This issue is about Mimir itself (not a system I'm assessing with it).
- [ ] I've read [the constitution](../blob/main/docs/instructions.md) and understand
      Mimir is a staging-only tool.
