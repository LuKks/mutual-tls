const https = require('https')
const test = require('brittle')
const bind = require('like-bind')
const MutualTLS = require('./index.js')

test('basic', function (t) {
  t.plan(4)

  const root = new MutualTLS()

  t.ok(root.key)
  t.ok(root.ca)

  const server = root.authorize('example.com')

  t.ok(server.key)
  t.ok(server.cert)
})

test('from', function (t) {
  t.plan(6)

  const root = new MutualTLS()

  const clone = MutualTLS.from({
    key: root.key,
    ca: root.ca
  })

  t.alike(root.key, clone.key)
  t.alike(root.ca, clone.ca)

  // Avoid references
  t.not(root.key, clone.key)
  t.not(root.ca, clone.ca)

  const client = clone.authorize('Client Test')

  t.ok(client.key)
  t.ok(client.cert)
})

test('from - missing root options', function (t) {
  t.plan(2)

  const root = new MutualTLS()

  try {
    MutualTLS.from({
      key: root.key
    })

    t.fail()
  } catch (err) {
    t.is(err.message, 'Missing certificate')
  }

  try {
    MutualTLS.from({
      ca: root.ca
    })

    t.fail()
  } catch (err) {
    t.is(err.message, 'Missing key pair or private key')
  }
})

test('https - domain', async function (t) {
  t.plan(3)

  const COMMON_NAME = 'localhost'

  const root = new MutualTLS()
  const serverCert = root.authorize(COMMON_NAME)
  const clientCert = root.authorize('Test Client')

  const server = await createServer(t, root, serverCert, '127.0.0.1')

  const response = await httpsRequest(root, clientCert, {
    hostname: COMMON_NAME,
    port: server.address().port,
    path: '/',
    method: 'GET'
  })

  t.ok(response.req.socket.authorized)
  t.is(response.data, 'Hello World!')

  try {
    await httpsRequest(root, clientCert, {
      hostname: '127.0.0.1',
      port: server.address().port,
      path: '/',
      method: 'GET'
    })
  } catch (err) {
    t.is(err.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
  }
})

test('https - ip', async function (t) {
  t.plan(3)

  const COMMON_NAME = '127.0.0.1'

  const root = new MutualTLS()
  const serverCert = root.authorize(COMMON_NAME)
  const clientCert = root.authorize('Test Client')

  const server = await createServer(t, root, serverCert, '127.0.0.1')

  const response = await httpsRequest(root, clientCert, {
    hostname: COMMON_NAME,
    port: server.address().port,
    path: '/',
    method: 'GET'
  })

  t.ok(response.req.socket.authorized)
  t.is(response.data, 'Hello World!')

  try {
    await httpsRequest(root, clientCert, {
      hostname: 'localhost',
      port: server.address().port,
      path: '/',
      method: 'GET'
    })
  } catch (err) {
    t.is(err.code, 'ERR_TLS_CERT_ALTNAME_INVALID')
  }
})

test('https - multiple alt names', async function (t) {
  t.plan(4)

  const root = new MutualTLS()
  const serverCert = root.authorize(['localhost', '127.0.0.1'])
  const clientCert = root.authorize('Test Client')

  const server = await createServer(t, root, serverCert, '127.0.0.1')

  const response1 = await httpsRequest(root, clientCert, {
    hostname: 'localhost',
    port: server.address().port,
    path: '/',
    method: 'GET'
  })

  t.ok(response1.req.socket.authorized)
  t.is(response1.data, 'Hello World!')

  const response2 = await httpsRequest(root, clientCert, {
    hostname: '127.0.0.1',
    port: server.address().port,
    path: '/',
    method: 'GET'
  })

  t.ok(response2.req.socket.authorized)
  t.is(response2.data, 'Hello World!')
})

async function createServer (t, root, crt, address) {
  const server = https.createServer({
    ca: root.ca,
    key: crt.key,
    cert: crt.cert,
    requestCert: true,
    rejectUnauthorized: true
  })

  server.on('request', function (req, res) {
    res.writeHead(200)
    res.end('Hello World!')
  })

  await bind.listen(server, 0, address)

  t.teardown(() => bind.close(server))

  return server
}

function httpsRequest (root, crt, options) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      ca: root.ca,
      key: crt.key,
      cert: crt.cert,
      rejectUnauthorized: true,
      ...options
    }, function (res) {
      let data = ''

      res.on('data', function (chunk) {
        data += chunk.toString()
      })

      res.on('end', function () {
        resolve({ req, res, data })
      })

      res.on('error', function (err) {
        reject(err)
      })
    })

    req.on('error', function (err) {
      reject(err)
    })

    req.end()
  })
}
