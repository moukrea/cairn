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
