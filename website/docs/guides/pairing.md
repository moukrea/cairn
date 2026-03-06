---
sidebar_position: 1
title: "Pairing Methods"
---

import LanguageTabs from '@site/src/components/LanguageTabs';
import TabItem from '@theme/TabItem';

# Pairing Methods

Pairing establishes mutual trust between two devices using a shared secret. cairn supports three pairing methods: PIN, QR code, and link. One peer initiates the pairing, and the other responds.

## PIN Pairing

The most common method. The initiator generates a short PIN code and displays it. The responder types it in.

### Initiator: Generate PIN

<LanguageTabs>
<TabItem value="rust">

```rust
let pairing_data = node.pair_generate_pin().await?;
println!("PIN: {}", pairing_data.pin); // e.g., "A1B2-C3D4"
println!("Waiting for peer...");
// Blocks until the responder enters the PIN
let peer_id = pairing_data.peer_id;
println!("Paired with: {}", peer_id);
```

</TabItem>
<TabItem value="typescript">

```typescript
const { pin, peerId } = await node.pairGeneratePin();
console.log(`PIN: ${pin}`); // e.g., "A1B2-C3D4"
console.log('Waiting for peer...');
console.log(`Paired with: ${peerId}`);
```

</TabItem>
<TabItem value="go">

```go
data, err := node.PairGeneratePin()
if err != nil { log.Fatal(err) }
fmt.Println("PIN:", data.Pin) // e.g., "A1B2-C3D4"
fmt.Println("Waiting for peer...")
fmt.Println("Paired with:", data.PeerID)
```

</TabItem>
<TabItem value="python">

```python
data = await node.pair_generate_pin()
print(f"PIN: {data.pin}")  # e.g., "A1B2-C3D4"
print("Waiting for peer...")
print(f"Paired with: {data.peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$data = $node->pairGeneratePin();
echo "PIN: " . $data->pin . "\n"; // e.g., "A1B2-C3D4"
echo "Waiting for peer...\n";
echo "Paired with: " . $data->peerId . "\n";
```

</TabItem>
</LanguageTabs>

### Responder: Enter PIN

The responder enters the PIN displayed by the initiator.

<LanguageTabs>
<TabItem value="rust">

```rust
let peer_id = node.pair_enter_pin("A1B2-C3D4").await?;
println!("Paired with: {}", peer_id);
```

</TabItem>
<TabItem value="typescript">

```typescript
const peerId = await node.pairEnterPin('A1B2-C3D4');
console.log(`Paired with: ${peerId}`);
```

</TabItem>
<TabItem value="go">

```go
peerId, err := node.PairEnterPin("A1B2-C3D4")
if err != nil { log.Fatal(err) }
fmt.Println("Paired with:", peerId)
```

</TabItem>
<TabItem value="python">

```python
peer_id = await node.pair_enter_pin("A1B2-C3D4")
print(f"Paired with: {peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$peerId = $node->pairEnterPin('A1B2-C3D4');
echo "Paired with: " . $peerId . "\n";
```

</TabItem>
</LanguageTabs>

## QR Code Pairing

The initiator generates QR data that the responder scans with a camera. This is useful for mobile-to-mobile or mobile-to-desktop pairing where typing a PIN is inconvenient.

### Generating the QR Code

cairn provides the raw QR data string. Use a QR code library to render it as an image:

| Language   | Library                        | Install                                      |
|------------|--------------------------------|----------------------------------------------|
| Rust       | `qrcode`                       | `cargo add qrcode`                           |
| TypeScript | `qrcode`                       | `npm install qrcode`                         |
| Go         | `github.com/skip2/go-qrcode`   | `go get github.com/skip2/go-qrcode`          |
| Python     | `qrcode`                       | `pip install qrcode`                         |
| PHP        | `endroid/qr-code`              | `composer require endroid/qr-code`           |

<LanguageTabs>
<TabItem value="rust">

```rust
use qrcode::QrCode;

let qr_data = node.pair_generate_qr().await?;
let code = QrCode::new(&qr_data.data)?;
let image = code.render::<char>().build();
println!("{}", image);
println!("Waiting for peer to scan...");
let peer_id = qr_data.peer_id;
```

</TabItem>
<TabItem value="typescript">

```typescript
import QRCode from 'qrcode';

const qrData = await node.pairGenerateQr();
const qrString = await QRCode.toString(qrData.data, { type: 'terminal' });
console.log(qrString);
console.log('Waiting for peer to scan...');
const peerId = qrData.peerId;
```

</TabItem>
<TabItem value="go">

```go
import qrcode "github.com/skip2/go-qrcode"

qrData, err := node.PairGenerateQR()
if err != nil { log.Fatal(err) }
qr, _ := qrcode.New(qrData.Data, qrcode.Medium)
fmt.Println(qr.ToSmallString(false))
fmt.Println("Waiting for peer to scan...")
peerId := qrData.PeerID
```

</TabItem>
<TabItem value="python">

```python
import qrcode

qr_data = await node.pair_generate_qr()
qr = qrcode.QRCode()
qr.add_data(qr_data.data)
qr.print_ascii()
print("Waiting for peer to scan...")
peer_id = qr_data.peer_id
```

</TabItem>
<TabItem value="php">

```php
use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;

$qrData = $node->pairGenerateQr();
$qr = QrCode::create($qrData->data);
$writer = new PngWriter();
$result = $writer->write($qr);
$result->saveToFile('/tmp/cairn-pairing.png');
echo "QR saved to /tmp/cairn-pairing.png\n";
echo "Waiting for peer to scan...\n";
$peerId = $qrData->peerId;
```

</TabItem>
</LanguageTabs>

### Scanning the QR Code

The responder scans the QR code and passes the decoded data to cairn:

<LanguageTabs>
<TabItem value="rust">

```rust
let peer_id = node.pair_scan_qr(&scanned_data).await?;
println!("Paired with: {}", peer_id);
```

</TabItem>
<TabItem value="typescript">

```typescript
const peerId = await node.pairScanQr(scannedData);
console.log(`Paired with: ${peerId}`);
```

</TabItem>
<TabItem value="go">

```go
peerId, err := node.PairScanQR(scannedData)
if err != nil { log.Fatal(err) }
fmt.Println("Paired with:", peerId)
```

</TabItem>
<TabItem value="python">

```python
peer_id = await node.pair_scan_qr(scanned_data)
print(f"Paired with: {peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$peerId = $node->pairScanQr($scannedData);
echo "Paired with: " . $peerId . "\n";
```

</TabItem>
</LanguageTabs>

## Link Pairing

The initiator generates a URI that can be shared via any channel (email, SMS, chat). The responder opens the link to complete pairing. This is useful for remote pairing when devices are not physically together.

### Initiator: Generate Link

<LanguageTabs>
<TabItem value="rust">

```rust
let link_data = node.pair_generate_link().await?;
println!("Pairing link: {}", link_data.uri);
println!("Share this link with your peer.");
let peer_id = link_data.peer_id;
```

</TabItem>
<TabItem value="typescript">

```typescript
const linkData = await node.pairGenerateLink();
console.log(`Pairing link: ${linkData.uri}`);
console.log('Share this link with your peer.');
const peerId = linkData.peerId;
```

</TabItem>
<TabItem value="go">

```go
linkData, err := node.PairGenerateLink()
if err != nil { log.Fatal(err) }
fmt.Println("Pairing link:", linkData.URI)
fmt.Println("Share this link with your peer.")
peerId := linkData.PeerID
```

</TabItem>
<TabItem value="python">

```python
link_data = await node.pair_generate_link()
print(f"Pairing link: {link_data.uri}")
print("Share this link with your peer.")
peer_id = link_data.peer_id
```

</TabItem>
<TabItem value="php">

```php
$linkData = $node->pairGenerateLink();
echo "Pairing link: " . $linkData->uri . "\n";
echo "Share this link with your peer.\n";
$peerId = $linkData->peerId;
```

</TabItem>
</LanguageTabs>

### Responder: Accept Link

<LanguageTabs>
<TabItem value="rust">

```rust
let peer_id = node.pair_from_link(&uri).await?;
println!("Paired with: {}", peer_id);
```

</TabItem>
<TabItem value="typescript">

```typescript
const peerId = await node.pairFromLink(uri);
console.log(`Paired with: ${peerId}`);
```

</TabItem>
<TabItem value="go">

```go
peerId, err := node.PairFromLink(uri)
if err != nil { log.Fatal(err) }
fmt.Println("Paired with:", peerId)
```

</TabItem>
<TabItem value="python">

```python
peer_id = await node.pair_from_link(uri)
print(f"Paired with: {peer_id}")
```

</TabItem>
<TabItem value="php">

```php
$peerId = $node->pairFromLink($uri);
echo "Paired with: " . $peerId . "\n";
```

</TabItem>
</LanguageTabs>

## Choosing a Pairing Method

| Method | Best For                                    | Requires             |
|--------|---------------------------------------------|----------------------|
| PIN    | Same room, quick pairing                    | Visual/verbal contact |
| QR     | Mobile devices, camera available            | Camera + display      |
| Link   | Remote pairing, devices not co-located      | Messaging channel     |

All three methods provide the same level of security. The choice depends on the user experience you want to provide.

<details>
<summary>How it works: SPAKE2</summary>

All three pairing methods use **SPAKE2 (Simple Password Authenticated Key Exchange)** under the hood.

1. **Shared secret derivation**: The PIN, QR data, or link URI contains a shared secret that both peers know.

2. **SPAKE2 exchange**: Both parties perform a SPAKE2 handshake using the shared secret. SPAKE2 is designed so that neither party reveals the secret during the exchange -- even if an attacker observes every message, they cannot determine the secret or derive the session key.

3. **Noise XX bootstrap**: The shared key from SPAKE2 is used to authenticate the initial Noise XX handshake, which establishes the encrypted session with forward secrecy via the Double Ratchet protocol.

This means that even a short 8-character PIN provides strong security: an attacker who intercepts the pairing exchange cannot brute-force the PIN from the observed messages.

</details>
