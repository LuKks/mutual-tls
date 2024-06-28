const crypto = require('crypto')
const forge = require('node-forge')

const RSA_KEY_SIZE = 2048
const ROOT_COMMON_NAME = 'Generic CA'
const ROOT_NOT_AFTER = 365 * 86400
const CERT_NOT_AFTER = 90 * 86400

module.exports = class MutualTLS {
  constructor (opts = {}, root) {
    this._keyPair = null
    this._cert = null
    this._pem = null

    if (!root) this._createCA(opts)
    else this._loadCA(root)
  }

  _createCA (opts) {
    const keyPair = generateKeyPair(opts.bits || RSA_KEY_SIZE)
    const cert = forge.pki.createCertificate()

    const attributes = defaultAttributes(opts.name || ROOT_COMMON_NAME)
    const extensions = defaultExtensionsRoot()

    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey)
    cert.serialNumber = generateSerialNumber()

    cert.validity.notBefore = new Date(Date.now() - 86400 * 1000)
    cert.validity.notAfter = new Date(Date.now() + (opts.expiry || ROOT_NOT_AFTER) * 1000)

    cert.setSubject(attributes)
    cert.setIssuer(attributes)
    cert.setExtensions(extensions)

    cert.sign(forge.pki.privateKeyFromPem(keyPair.privateKey), forge.md.sha256.create())

    this._keyPair = keyPair
    this._cert = cert
    this._pem = Buffer.from(forge.pki.certificateToPem(cert))
  }

  _loadCA (root) {
    if (!root.ca) throw new Error('Missing certificate')
    if (!root.keyPair && !root.key) throw new Error('Missing key pair or private key')

    this._keyPair = toKeyPair(root)
    this._cert = forge.pki.certificateFromPem(root.ca)
    this._pem = Buffer.from(forge.pki.certificateToPem(this._cert))
  }

  get key () {
    return this._keyPair.privateKey
  }

  get ca () {
    return this._pem
  }

  authorize (name, opts = {}) {
    if (!name) throw new Error('Common name is required')
    if (typeof name === 'string') name = [name]

    const keyPair = generateKeyPair(opts.bits || RSA_KEY_SIZE)
    const cert = forge.pki.createCertificate()

    cert.publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey)
    cert.serialNumber = generateSerialNumber()

    cert.validity.notBefore = new Date(Date.now() - 86400 * 1000)
    cert.validity.notAfter = new Date(Date.now() + (opts.expiry || CERT_NOT_AFTER) * 1000)

    const attributes = defaultAttributes(name[0])
    const issuer = this._cert.issuer.attributes
    const extensions = defaultExtensionsCert(name)

    cert.setSubject(attributes)
    cert.setIssuer(issuer)
    cert.setExtensions(extensions)

    cert.sign(forge.pki.privateKeyFromPem(this._keyPair.privateKey), forge.md.sha256.create())

    return {
      key: keyPair.privateKey,
      cert: Buffer.from(forge.pki.certificateToPem(cert))
    }
  }

  static from (root) {
    return new this(null, root)
  }

  static keyPair (bits) {
    return generateKeyPair(bits || RSA_KEY_SIZE)
  }

  static serialNumber () {
    return generateSerialNumber()
  }

  static toPublicKey (privateKey) {
    return privateToPublicKey(privateKey)
  }
}

function generateKeyPair (bits) {
  const keyPair = forge.pki.rsa.generateKeyPair(bits)

  return {
    publicKey: Buffer.from(forge.pki.publicKeyToPem(keyPair.publicKey)),
    privateKey: Buffer.from(forge.pki.privateKeyToPem(keyPair.privateKey))
  }
}

function privateToPublicKey (privateKey) {
  const pk = forge.pki.privateKeyFromPem(privateKey)
  const publicKey = forge.pki.rsa.setPublicKey(pk.n, pk.e)

  return Buffer.from(forge.pki.publicKeyToPem(publicKey))
}

function generateSerialNumber () {
  return crypto.randomUUID().replace(/-/g, '')
}

function toKeyPair (root) {
  if (root.keyPair) {
    return {
      publicKey: Buffer.from(root.keyPair.publicKey),
      privateKey: Buffer.from(root.keyPair.privateKey)
    }
  }

  if (root.key) {
    return {
      publicKey: Buffer.from(root.publicKey || privateToPublicKey(root.key)),
      privateKey: Buffer.from(root.key)
    }
  }

  throw new Error('Could not get key pair')
}

function defaultAttributes (commonName) {
  return [
    {
      name: 'commonName',
      value: commonName
    }
  ]
}

function defaultExtensionsRoot () {
  return [
    {
      name: 'basicConstraints',
      cA: true
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: true,
      emailProtection: true,
      timeStamping: true
    },
    {
      name: 'nsCertType',
      client: true,
      server: true,
      email: true,
      objsign: true,
      sslCA: true,
      emailCA: true,
      objCA: true
    },
    {
      name: 'subjectKeyIdentifier'
    }
  ]
}

function defaultExtensionsCert (altNames) {
  const ALTNAME_TYPE = {
    DNS: 2,
    IP: 7
  }

  return [
    {
      name: 'basicConstraints',
      cA: false
    },
    {
      name: 'keyUsage',
      keyCertSign: false,
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: true,
      dataEncipherment: true
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true,
      codeSigning: false,
      emailProtection: false,
      timeStamping: false
    },
    {
      name: 'nsCertType',
      client: true,
      server: true,
      email: false,
      objsign: false,
      sslCA: false,
      emailCA: false,
      objCA: false
    },
    {
      name: 'subjectKeyIdentifier'
    },
    {
      name: 'subjectAltName',
      altNames: altNames.map(getAltName)
    }
  ]

  function getAltName (name) {
    if (name.match(/^[\d.]+$/)) {
      return { type: ALTNAME_TYPE.IP, ip: name }
    }

    return { type: ALTNAME_TYPE.DNS, value: name }
  }
}
