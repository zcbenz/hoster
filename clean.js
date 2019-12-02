#!/usr/bin/env node

// Go through blacklists in /etc/hosts and remove them.

const dns = require('dns').promises
const fs = require('fs').promises
const util = require('util')
const probe = util.promisify(require('./lib/tcp-ping').probe)

// Cache scanned domains.
const deadHosts = new Set
const liveHosts = new Set

// Clean any file passed, but clean /etc/hosts by default.
let hostFiles = ['/etc/hosts']
if (process.argv.length > 2)
  hostFiles = process.argv.slice(2)
hostFiles.forEach(clean)

async function clean(hostFile) {
  const content = String(await fs.readFile(hostFile))
  let output = ''
  for (let line of content.split('\n')) {
    line = line.trim()
    if (line.startsWith('#') /* comment */||
        /^\s*$/.test(line)   /* spaces */) {
      output += line + '\n'
      continue
    }

    // Parse line: |address domain ...|.
    const components = line.split(/\s+/)
    if (components.length < 2) {
      console.error('Invalid line:', line)
      process.exit(1)
    }

    // Test if host is alive.
    if (['0.0.0.0', '::'].includes(components[0])) {
      if (!isHostAvailable(components[1]))
        continue
    }
    output += components.join(' ') + '\n'
  }
  await fs.writeFile(hostFile, output)
}

function isHostAvailable(host) {
  if (liveHosts.has(host))
    return true
  if (deadHosts.has(host))
    return false
  try {
    const address = (await dns.resolve(host))[0]
    if (!await probe(address, 80) && !await probe(address, 443))
      throw new Error
  } catch {
    console.log('Dead domain:', host)
    deadHosts.add(host)
    return false
  }
  liveHosts.add(host)
  return true
}
