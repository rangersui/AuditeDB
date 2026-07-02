# End-to-end auth

## One line

AuditeDB can act as a zero-knowledge relay. Client and sidecar use their own
keypairs for signing and encryption; AuditeDB only stores ciphertext bytes.

Signatures replace passwords. A folder of trusted public keys replaces the user
database.

## Core finding

AuditeDB only stores bytes. Encrypted, signed bytes are still bytes. Both ends
hold their own keypairs and pass signed-then-encrypted blobs through AuditeDB,
with the core participating in nothing and learning nothing. This gives
application-level confidentiality, authentication, and authorisation without
adding an identity system to AuditeDB itself.

## Architecture

```text
client                         AuditeDB shelf          sidecar
  |                                |                     |
  | sign(payload, client.key)      |                     |
  | encrypt(bundle, sidecar.pub)   |                     |
  |---- PUT /home/channel/.../req ->|                     |
  |                                | stored ciphertext   |
  |                                |                     |
  |                                | GET /home/channel/.../req
  |                                |------------------->|
  |                                |       decrypt(sidecar.key)
  |                                |       verify(client.pub)
  |                                |       check nonce + timestamp
  |                                |       authorise + compute
  |                                |       sign + encrypt reply
  |<--- GET /home/channel/.../reply|<-- PUT reply -------|
  | decrypt(client.key)            |                     |
  | verify(sidecar.pub)            |                     |
```

All channel keys should live under a durable, audited namespace such as
`home/channel/...`. Bare paths such as `/channel/alice/request` would
canonicalise to `home/channel/alice/request`, but explicit prefixes are
clearer.

## Two independent auth layers

```text
Layer 1: AuditeDB token
  -> can this caller read/write this world path?
  -> controls PUT/GET authority at the HTTP shelf
  -> if leaked: attacker can read ciphertext, but cannot decrypt or impersonate

Layer 2: E2E keypair
  -> who signed this payload?
  -> what can that verified identity do?
  -> checked by the sidecar, not by AuditeDB
  -> private key never crosses AuditeDB
```

The two layers are independent. Holding an AuditeDB write token does not let an
attacker impersonate Alice: messages without a valid signature from Alice's
private key are rejected by the sidecar.

## Keys replace passwords

```text
valid signature from a key in trusted_keys/  -> identified
no valid signature                            -> denied
```

What disappears:

```text
- username             the public key in trusted_keys/ is the identity
- password             the private key is the credential, never transmitted
- password database    no credential table to leak
- session cookie       every request carries a fresh signed payload
- JWT/OAuth            not needed for this local trust shape
- password phishing    there is no password to phish
```

Private-key theft is still endpoint compromise. Malware, bad backups, or
copying a key to the wrong machine can steal a key. That compromise affects the
endpoint identity until the public key is removed or rotated; it is not an
AuditeDB credential leak.

## Minimum implementation shape

Use sign-then-encrypt with nonce and timestamp. Encryption should be hybrid:
AES-GCM encrypts the bundle, and RSA-OAEP or another public-key primitive wraps
only the AES key. Do not RSA-encrypt a full message directly.

The snippets below show the shape. For production, prefer a vetted protocol
layer such as JWS+JWE, age, libsodium sealed boxes plus detached signatures, or
Noise.

### Generate keypairs

Raw public-key files are enough. This is closer to SSH `authorized_keys` than
to TLS certificate authority chains.

```bash
# client signing/encryption keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client.key
openssl pkey -in client.key -pubout -out client.pub

# sidecar signing/encryption keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out sidecar.key
openssl pkey -in sidecar.key -pubout -out sidecar.pub
```

Exchange public keys once over a secure out-of-band channel: in person, Signal,
USB stick, or another channel the user already trusts. The sidecar stores
client public keys in `trusted_keys/`.

### Client: sign then encrypt

```python
import base64, json, secrets, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

client_priv = serialization.load_pem_private_key(open("client.key", "rb").read(), password=None)
sidecar_pub = serialization.load_pem_public_key(open("sidecar.pub", "rb").read())

payload = json.dumps({
    "who": "alice",
    "action": "read_sensor",
    "nonce": secrets.token_hex(16),
    "timestamp": int(time.time()),
}).encode()

signature = client_priv.sign(
    payload,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)

bundle = json.dumps({
    "payload_b64": base64.b64encode(payload).decode(),
    "signature_b64": base64.b64encode(signature).decode(),
}).encode()

aes_key = AESGCM.generate_key(bit_length=256)
iv = secrets.token_bytes(12)
ciphertext = AESGCM(aes_key).encrypt(iv, bundle, None)
wrapped_key = sidecar_pub.encrypt(
    aes_key,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)

envelope = json.dumps({
    "wrapped_key_b64": base64.b64encode(wrapped_key).decode(),
    "iv_b64": base64.b64encode(iv).decode(),
    "ciphertext_b64": base64.b64encode(ciphertext).decode(),
}).encode()

requests.put(
    "http://localhost:3105/home/channel/alice/request",
    headers={"Authorization": "Bearer WRITE_TOKEN"},
    data=envelope,
)
```

The JSON above is application payload inside an encrypted blob. It is not a core
AuditeDB world-operation envelope.

### Sidecar: decrypt, verify, then authorise

```python
import base64, json, time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

sidecar_priv = serialization.load_pem_private_key(open("sidecar.key", "rb").read(), password=None)
seen_nonces = set()
MAX_AGE_SECONDS = 60

def load_trusted_key(identity):
    return serialization.load_pem_public_key(open(f"trusted_keys/{identity}.pub", "rb").read())

def handle_request(world):
    r = requests.get(f"http://localhost:3105{world}", headers={"Authorization": "Bearer READ_TOKEN"})
    env = json.loads(r.content)

    aes_key = sidecar_priv.decrypt(
        base64.b64decode(env["wrapped_key_b64"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    bundle = AESGCM(aes_key).decrypt(
        base64.b64decode(env["iv_b64"]),
        base64.b64decode(env["ciphertext_b64"]),
        None,
    )

    inner = json.loads(bundle)
    payload = base64.b64decode(inner["payload_b64"])
    signature = base64.b64decode(inner["signature_b64"])
    msg = json.loads(payload)

    try:
        load_trusted_key(msg["who"]).verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except (InvalidSignature, FileNotFoundError):
        return

    if abs(time.time() - msg["timestamp"]) > MAX_AGE_SECONDS:
        return
    if msg["nonce"] in seen_nonces:
        return
    seen_nonces.add(msg["nonce"])

    if is_authorised(msg["who"], msg["action"]):
        result = execute(msg["action"])
        put_signed_encrypted_reply(world + "/reply", msg["who"], result)
```

## User management equals one folder

```text
trusted_keys/
|-- alice.pub
|-- bob.pub
`-- charlie.pub

Add a user:     drop the public key file in.
Remove a user:  remove the public key file.
Change rights:  sidecar maps identity -> permissions.
```

This is the SSH `authorized_keys` model.

## Security properties

```text
authentication   signature over payload verified against trusted_keys/<who>.pub
authorisation    sidecar maps verified identity -> permission table
confidentiality  encrypted body; AuditeDB sees only ciphertext bytes
integrity        signature plus AEAD tag catch tampering
replay defence   nonce cache plus timestamp window
zero knowledge   AuditeDB stores opaque bytes
```

## Attack-surface analysis

```text
attacker holds an AuditeDB read token:
  can read ciphertext -> cannot decrypt

attacker holds an AuditeDB write token:
  can PUT garbage or claimed identity -> signature check fails

attacker holds a public key:
  public keys are public by design

attacker holds a private key:
  can impersonate that endpoint until the key is revoked
  -> endpoint compromise, not AuditeDB compromise
  -> remove or rotate the trusted public key and investigate the machine
```

## Traps

- Do not treat encryption as authentication. The sidecar must verify a signature
  from a trusted public key before acting.
- Do not paste the snippets above into a security-critical product without
  review; use them to understand the shape.
- Nonce caches need TTL eviction or durable storage.
- Clock skew matters because timestamp checks assume roughly synchronized
  client and sidecar clocks.
- The first public-key exchange is the trust anchor. If a man-in-the-middle
  replaces it, the system trusts the wrong identity.
- Memory namespaces (`tmp/`, `dev/`, `sys/`) are not durable or audited; use
  `home/channel/...` unless losing the channel is acceptable.

## Related references

- `../SKILL.md` -- mental model and operational checklist.
- `flexible-deployment.md` -- layered defence and token topology.
- `async-client.md` -- sidecar communication patterns.
- `navigation.md` -- path-level operations.
