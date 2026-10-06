---
name: plystra-craft-design
description: "Plystra Craft rules for visual identity and interfaces. Use when designing, building, or reviewing anything people see or operate in a Plystra project: logos and identity, palette, typography, layout, imagery, motion, app and web UI, components, states, responsive behavior, and accessibility. Requires plystra-craft."
---

# Plystra design

Rules for how a Plystra project looks and how people operate it. They add to `plystra-craft`, which carries product behavior, interface copy, and brand relationships. If `plystra-craft` is not installed, tell the user to run `bunx --bun skills add plystra/craft --skill plystra-craft`.

Inspect the accepted identity, existing components and tokens, and supported devices before changing anything. The shipped product and its design system are the source of truth; preserve them unless replacing them is the task. Projects and sub-brands may have their own personality within these standards.

## Read what the work touches

| Work | Read |
| --- | --- |
| Identity, logo use, palette, type, layout, imagery, motion, screenshots, in any medium | [visual identity](references/visual-identity.md) |
| A digital interface: personality, hierarchy, components, forms, navigation, states, responsive layout, tokens, charts | [interface design](references/interface-design.md) |
| Keyboard, focus, contrast, reduced motion, touch, comprehension, language | [accessibility](references/accessibility.md) |
| Labels, empty states, error messages | `plystra-craft`: writing |
| An official website's search, sharing, and `/llms.txt` | `plystra-craft-website`, if installed |

Work without a digital interface does not need one; apply the identity and accessibility rules to its actual medium.

## Verify

Inspect the rendered result at supported desktop and mobile sizes, with keyboard and reduced motion where relevant. Use the [UI review checklist](assets/templates/ui-review-checklist.md) for visible interface changes. Report the checks performed and any states left unverified.

The [index](references/index.md) and [source ledger](references/sources.json) identify the canonical sources of this snapshot. Keep the [license](references/LICENSE) when reusing them.
\n