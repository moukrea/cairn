import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import CodeBlock from '@theme/CodeBlock';
import TabItem from '@theme/TabItem';
import LanguageTabs from '@site/src/components/LanguageTabs';
import styles from './index.module.css';

function Hero() {
  return (
    <section className={styles.hero}>
      <img
        src={useBaseUrl('/img/cairn.png')}
        alt="cairn logo"
        className={styles.heroLogo}
      />
      <h1 className={styles.heroTagline}>
        Universal peer-to-peer connectivity library
      </h1>
      <p className={styles.heroSubtitle}>
        End-to-end encrypted messaging across five languages.
        No infrastructure required to get started.
      </p>
      <div className={styles.heroCtas}>
        <Link
          className={styles.ctaPrimary}
          to="/docs/getting-started/installation"
        >
          Get Started
        </Link>
        <Link
          className={styles.ctaSecondary}
          href="https://github.com/moukrea/cairn"
        >
          View on GitHub
        </Link>
      </div>
    </section>
  );
}

const features = [
  {
    title: 'Five Languages, One Protocol',
    description:
      'Rust, TypeScript, Go, Python, and PHP implementations that fully interoperate over the same wire protocol.',
  },
  {
    title: 'Secure by Default',
    description:
      'Noise XX handshake with Double Ratchet for forward secrecy. Encryption is always on, not opt-in.',
  },
  {
    title: 'Progressive Infrastructure',
    description:
      'Start peer-to-peer with zero servers. Add signaling and relay only when your deployment needs it.',
  },
];

function Features() {
  return (
    <section className={styles.features}>
      <div className={styles.featuresContainer}>
        <h2 className={styles.sectionHeading}>Why cairn</h2>
        <p className={styles.sectionSubheading}>
          A single protocol for direct, encrypted communication between peers --
          regardless of language or platform.
        </p>
        <div className={styles.featureGrid}>
          {features.map((feature) => (
            <div key={feature.title} className={styles.featureCard}>
              <h3>{feature.title}</h3>
              <p>{feature.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

const codeExamples: Record<string, { language: string; code: string }> = {
  rust: {
    language: 'rust',
    code: `use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
let pairing = node.pair_generate_pin().await?;
println!("PIN: {}", pairing.pin);
// Responder enters PIN, then:
let session = node.connect(&peer_id).await?;
session.send("chat", b"hello").await?;`,
  },
  typescript: {
    language: 'typescript',
    code: `import { Node } from 'cairn-p2p';

const node = await Node.create();
const { pin } = await node.pairGeneratePin();
console.log(\`PIN: \${pin}\`);
// Responder enters PIN, then:
const session = await node.connect(peerId);
await session.send('chat', Buffer.from('hello'));`,
  },
  go: {
    language: 'go',
    code: `import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, _ := cairn.Create()
data, _ := node.PairGeneratePin()
fmt.Println("PIN:", data.Pin)
// Responder enters PIN, then:
session, _ := node.Connect(peerId)
session.Send("chat", []byte("hello"))`,
  },
  python: {
    language: 'python',
    code: `from cairn import create

node = await create()
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")
# Responder enters PIN, then:
session = await node.connect(peer_id)
await session.send("chat", b"hello")`,
  },
  php: {
    language: 'php',
    code: `use Cairn\\Node;

$node = Node::create();
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\\n";
// Responder enters PIN, then:
$session = $node->connect($peerId);
$session->send('chat', 'hello');`,
  },
};

function CodeExample() {
  return (
    <section className={styles.codeExample}>
      <div className={styles.codeExampleContainer}>
        <h2 className={styles.sectionHeading}>Get started in minutes</h2>
        <p className={styles.sectionSubheading}>
          Pair two nodes, establish a session, and start sending messages.
        </p>
        <LanguageTabs>
          {Object.entries(codeExamples).map(([key, { language, code }]) => (
            <TabItem key={key} value={key}>
              <CodeBlock language={language}>{code}</CodeBlock>
            </TabItem>
          ))}
        </LanguageTabs>
      </div>
    </section>
  );
}

const tiers = [
  {
    name: 'Tier 0',
    label: 'Peer-to-peer only',
    attributes: [
      ['Setup', 'None'],
      ['NAT traversal', 'Public STUN, best-effort'],
      ['Discovery', '5-30s (DHT/mDNS)'],
      ['Offline messages', 'No'],
      ['Relay', 'No'],
      ['Multi-device', 'Manual'],
      ['Cost', 'Free'],
    ],
  },
  {
    name: 'Tier 1',
    label: 'With signaling',
    attributes: [
      ['Setup', '2 Docker containers'],
      ['NAT traversal', 'TURN relay, symmetric NAT'],
      ['Discovery', '<1s (signaling)'],
      ['Offline messages', 'No'],
      ['Relay', 'Yes'],
      ['Multi-device', 'Manual'],
      ['Cost', 'Free (Cloudflare) or ~$5/mo VPS'],
    ],
  },
  {
    name: 'Tier 2',
    label: 'Full stack',
    attributes: [
      ['Setup', '3 Docker containers'],
      ['NAT traversal', 'Full'],
      ['Discovery', '<1s'],
      ['Offline messages', 'Yes (store-and-forward)'],
      ['Relay', 'Yes'],
      ['Multi-device', 'Automatic (hub)'],
      ['Cost', 'Same + storage'],
    ],
  },
];

function InfrastructureTiers() {
  return (
    <section className={styles.tiers}>
      <div className={styles.tiersContainer}>
        <h2 className={styles.sectionHeading}>Infrastructure tiers</h2>
        <p className={styles.sectionSubheading}>
          Deploy what you need. Each tier builds on the previous one.
        </p>
        <div className={styles.tierGrid}>
          {tiers.map((tier) => (
            <div key={tier.name} className={styles.tierCard}>
              <h3>{tier.name}</h3>
              <span className={styles.tierLabel}>{tier.label}</span>
              <dl>
                {tier.attributes.map(([key, value]) => (
                  <React.Fragment key={key}>
                    <dt>{key}</dt>
                    <dd>{value}</dd>
                  </React.Fragment>
                ))}
              </dl>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function FooterCta() {
  return (
    <section className={styles.footerCta}>
      <h2 className={styles.sectionHeading}>Start building</h2>
      <p className={styles.footerCtaText}>
        Read the docs, pick your language, and have two peers talking in minutes.
      </p>
      <div className={styles.footerCtaButtons}>
        <Link
          className={styles.ctaPrimary}
          to="/docs/getting-started/installation"
        >
          Read the Docs
        </Link>
        <Link
          className={styles.ctaSecondary}
          href="https://github.com/moukrea/cairn"
        >
          View on GitHub
        </Link>
      </div>
    </section>
  );
}

export default function Home(): React.ReactElement {
  return (
    <Layout title="Home" description="Universal peer-to-peer connectivity library">
      <Hero />
      <Features />
      <CodeExample />
      <InfrastructureTiers />
      <FooterCta />
    </Layout>
  );
}
