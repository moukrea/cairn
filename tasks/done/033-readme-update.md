# Task 033: README Documentation Link Update

## Status
done

## Dependencies
- 001-docusaurus-scaffolding (needs docs site to exist before linking to it)
- 002-sidebar-css-assets (needs site structure in place before linking)

## Spec References
- spec/05-infrastructure-content.md (README Update Instructions)

## Scope
Update the root README.md to add a prominent link to the documentation site. Keep the README concise — it serves as a landing page, not comprehensive docs.

## Acceptance Criteria
- [x] Root `README.md` contains a "Documentation" section near the top
- [x] Documentation section links to `https://moukrea.github.io/cairn/`
- [x] Existing quick-start code examples in README are preserved
- [x] README remains concise and serves as a landing page

## Implementation Notes
Add a brief "Documentation" section near the top of the README:

```markdown
## Documentation

Full documentation is available at [moukrea.github.io/cairn](https://moukrea.github.io/cairn/).
```

Do NOT remove or modify existing content. Only add the documentation link section. Place it after the project description/badges but before the detailed content sections.

## Files to Create or Modify
- README.md (modify)

## Verification Commands
- Visual inspection of README.md
