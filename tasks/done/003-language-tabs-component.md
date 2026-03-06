# Task 003: LanguageTabs Component

## Status
done

## Dependencies
- 001-docusaurus-scaffolding (needs Docusaurus project with @docusaurus/theme-common)

## Spec References
- spec/01-docusaurus-setup.md (LanguageTabs Component section)

## Scope
Create the reusable `LanguageTabs` React component that wraps Docusaurus `<Tabs>` with a fixed set of language tabs (Rust, TypeScript, Go, Python, PHP). This component is used by the landing page and all documentation content tasks.

## Acceptance Criteria
- [x] `website/src/components/LanguageTabs.tsx` exists and exports a default React component
- [x] Component renders `<Tabs>` with `groupId="language"` and `queryString="lang"`
- [x] Tab labels are: `Rust`, `TypeScript`, `Go`, `Python`, `PHP`
- [x] Tab values are: `rust`, `typescript`, `go`, `python`, `php`
- [x] Default tab is `rust`
- [x] Selecting a tab persists across all LanguageTabs instances on the page (via Docusaurus groupId)
- [x] Component works correctly with Docusaurus MDX v3 parser (TabItem children nesting)

## Implementation Notes

### File: `website/src/components/LanguageTabs.tsx`

```typescript
import React from 'react';
import Tabs from '@theme/Tabs';

interface LanguageTabsProps {
  children: React.ReactNode;
}

export default function LanguageTabs({ children }: LanguageTabsProps): React.ReactElement {
  return (
    <Tabs
      groupId="language"
      queryString="lang"
      defaultValue="rust"
      values={[
        { label: 'Rust', value: 'rust' },
        { label: 'TypeScript', value: 'typescript' },
        { label: 'Go', value: 'go' },
        { label: 'Python', value: 'python' },
        { label: 'PHP', value: 'php' },
      ]}
    >
      {children}
    </Tabs>
  );
}
```

### Usage Pattern in MDX
```mdx
import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

<LanguageTabs>
<TabItem value="rust">

\`\`\`rust
// code here
\`\`\`

</TabItem>
<!-- ... other languages -->
</LanguageTabs>
```

The `groupId` synchronization is a built-in Docusaurus feature -- when one LanguageTabs instance changes, all others on the same page update. The `queryString` persists the selection in the URL.

## Files to Create or Modify
- website/src/components/LanguageTabs.tsx (new)

## Verification Commands
- `cd website && npm run build`
