# Skills for the Proxy Control MCP server

Instructions for a model on an operator's routine tasks over the panel's MCP tools
([docs/MCP.en.md](../docs/MCP.en.md), «Skills»; [docs/MCP.ru.md](../docs/MCP.ru.md), «Скиллы»).
One directory per skill, a `SKILL.md` with `name`/`description` frontmatter per the
[Agent Skills specification](https://agentskills.io/specification). Skills are written in English;
UI labels and field values the panel returns are quoted as they are.

Install on the machine running the client (not on the server):

```bash
cp -r skills/proxy-control-* ~/.claude/skills/    # Claude Code
cp -r skills/proxy-control-* ~/.agents/skills/    # Codex CLI and other clients reading the shared directory
```

| Skill | Task |
|---|---|
| [`proxy-control-granting-access`](proxy-control-granting-access/SKILL.md) | grant access, the subscription link, a client's nodes and protocols |
| [`proxy-control-morning-overview`](proxy-control-morning-overview/SKILL.md) | the state of the panel and its nodes, what happened in the last day |
| [`proxy-control-updating-components`](proxy-control-updating-components/SKILL.md) | checking for and installing component updates |
| [`proxy-control-diagnosing-access`](proxy-control-diagnosing-access/SKILL.md) | «the subscription is there but nothing works» |
| [`proxy-control-changing-routing`](proxy-control-changing-routing/SKILL.md) | a routing policy: preview, apply, rollback |

Editing a skill is like editing code: first the scenario without the skill (what the model gets
wrong), then the change, then the same scenario with the skill. The runs use the panel's read-only
tools; mutating calls are described in the scenario, never executed.
