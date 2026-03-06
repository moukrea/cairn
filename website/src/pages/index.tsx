import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
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
        End-to-end encrypted. Five languages. Zero infrastructure required.
      </p>
      <div className={styles.heroCtas}>
        <Link
          className="button button--primary button--lg"
          to="/docs/getting-started/installation"
        >
          Get Started
        </Link>
        <Link
          className="button button--secondary button--lg"
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
    description: 'Rust, TypeScript, Go, Python, PHP all interoperate.',
  },
  {
    title: 'Secure by Default',
    description: 'Noise XX + Double Ratchet, no opt-in required.',
  },
  {
    title: 'Zero to Production',
    description: 'Start with no infrastructure, add signaling/relay when needed.',
  },
];

function Features() {
  return (
    <section className={styles.features}>
      <div className={styles.featuresContainer}>
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

function CodeExample() {
  return (
    <section className={styles.codeExample}>
      <div className={styles.codeExampleContainer}>
        <h2>Get started in minutes</h2>
        <LanguageTabs>
          <TabItem value="rust">

{`\`\`\`rust
use cairn_p2p::{Node, CairnConfig, create};

let node = create(CairnConfig::default())?;
node.start().await?;
let pairing = node.pair_generate_pin().await?;
println!("PIN: {}", pairing.pin);
// Responder enters PIN, then:
let session = node.connect(&peer_id).await?;
session.send("chat", b"hello").await?;
\`\`\``}

          </TabItem>
          <TabItem value="typescript">

{`\`\`\`typescript
import { Node } from 'cairn-p2p';

const node = await Node.create();
const { pin } = await node.pairGeneratePin();
console.log(\`PIN: \${pin}\`);
// Responder enters PIN, then:
const session = await node.connect(peerId);
await session.send('chat', Buffer.from('hello'));
\`\`\``}

          </TabItem>
          <TabItem value="go">

{`\`\`\`go
import cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"

node, _ := cairn.Create()
data, _ := node.PairGeneratePin()
fmt.Println("PIN:", data.Pin)
// Responder enters PIN, then:
session, _ := node.Connect(peerId)
session.Send("chat", []byte("hello"))
\`\`\``}

          </TabItem>
          <TabItem value="python">

{`\`\`\`python
from cairn import create

node = await create()
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")
# Responder enters PIN, then:
session = await node.connect(peer_id)
await session.send("chat", b"hello")
\`\`\``}

          </TabItem>
          <TabItem value="php">

{`\`\`\`php
use Cairn\\Node;

$node = Node::create();
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\\n";
// Responder enters PIN, then:
$session = $node->connect($peerId);
$session->send('chat', 'hello');
\`\`\``}

          </TabItem>
        </LanguageTabs>
      </div>
    </section>
  );
}

const tiers = [
  {
    name: 'Tier 0',
    label: 'Zero Infrastructure',
    attributes: [
      ['Setup', 'None'],
      ['NAT traversal', 'Public STUN, best-effort'],
      ['Discovery speed', '5-30s (DHT/mDNS)'],
      ['Offline messages', 'No'],
      ['Always-on relay', 'No'],
      ['Multi-device sync', 'Manual'],
      ['Cost', 'Free'],
    ],
  },
  {
    name: 'Tier 1',
    label: 'Signaling + Relay',
    attributes: [
      ['Setup', '2 Docker containers'],
      ['NAT traversal', 'TURN relay, symmetric NAT'],
      ['Discovery speed', '<1s (signaling)'],
      ['Offline messages', 'No'],
      ['Always-on relay', 'Yes'],
      ['Multi-device sync', 'Manual'],
      ['Cost', 'Free (Cloudflare) or ~$5/mo VPS'],
    ],
  },
  {
    name: 'Tier 2',
    label: 'Server Peer',
    attributes: [
      ['Setup', '3 Docker containers'],
      ['NAT traversal', 'Full'],
      ['Discovery speed', '<1s'],
      ['Offline messages', 'Yes (store-and-forward)'],
      ['Always-on relay', 'Yes'],
      ['Multi-device sync', 'Automatic (hub)'],
      ['Cost', 'Same + storage'],
    ],
  },
];

function InfrastructureTiers() {
  return (
    <section className={styles.tiers}>
      <div className={styles.tiersContainer}>
        <h2>Infrastructure Tiers</h2>
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

export default function Home(): React.ReactElement {
  return (
    <Layout title="Home" description="Universal peer-to-peer connectivity library">
      <Hero />
      <Features />
      <CodeExample />
      <InfrastructureTiers />
    </Layout>
  );
}
