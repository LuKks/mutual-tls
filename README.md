# mutual-tls

Create your own Root CA, and new signed certificates

```
npm i mutual-tls
```

## Usage

```js
const MutualTLS = require('mutual-tls')

const root = new MutualTLS()
const server = root.authorize('127.0.0.1')
const client = root.authorize('Client Test')

console.log(root.key, root.ca)
console.log(server.key, server.cert)
console.log(client.key, client.cert)
```

Save `root.key` and `root.ca` to restore the root:

```js
const clone = MutualTLS.from({
  key: root.key,
  ca: root.ca
})

const crt = clone.authorize('Another Client')

console.log(crt.key, crt.cert)
```

## API

#### `const root = new MutualTLS([options])`

Create a new root certificate authority.

Options include:

```js
{
  name: 'Generic CA',
  bits: 2048,
  expiry: 365 * 86400
}
```

#### `root.key`

Buffer containing the private key in PEM format of the CA.

#### `root.ca`

Buffer containing the certificate in PEM format of the CA.

#### `const crt = root.authorize(names, [options])`

Create a new signed certificate. `names` can be a string or array.

The first name of `names` is used as the "commonName".

All of them `names` are used as "subjectAltName" (only DNS and IP).

Options include:

```js
{
  bits: 2048,
  expiry: 90 * 86400
}
```

#### `const root = MutualTLS.from({ key, ca })`

Restore a Root CA from its private key and certificate.

#### `const keyPair = MutualTLS.keyPair([bits])`

Creates a RSA key pair. `bits` defaults to 2048.

#### `const serialNumber = MutualTLS.serialNumber()`

Generates a new random serial number.

#### `const publicKey = MutualTLS.toPublicKey(privateKey)`

Re-generate the public key based on a private key.

## License

MIT
