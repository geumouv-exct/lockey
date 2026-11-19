import dns from 'node:dns';
import { Agent } from 'node:https';
import { BlockList } from 'node:net';

const allowedOrigin = 'https://api.example.test';
const blockedIPv4 = new BlockList();
for (const [address, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
]) {
  blockedIPv4.addSubnet(address, prefix);
}

const globalIPv6 = new BlockList();
globalIPv6.addSubnet('2000::', 3, 'ipv6');

const blockedIPv6 = new BlockList();
for (const [address, prefix] of [
  ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20],
]) {
  blockedIPv6.addSubnet(address, prefix, 'ipv6');
}

const agent = new Agent({
  lookup(hostname, options, callback) {
    // Resolve and filter inside socket creation so the connection uses the checked IP.
    dns.lookup(hostname, { ...options, all: true }, (error, addresses) => {
      if (error) return callback(error);

      const allowed = addresses.filter(({ address, family }) => {
        if (family === 4) return !blockedIPv4.check(address);
        return family === 6 && globalIPv6.check(address, 'ipv6')
          && !blockedIPv6.check(address, 'ipv6');
      });

      if (allowed.length === 0) return callback(new Error('No allowed destination IP'));
      if (options.all) return callback(null, allowed);
      return callback(null, allowed[0].address, allowed[0].family);
    });
  },
});

export function loadData(req, needle) {
  const value = req.query?.url;
  if (typeof value !== 'string') throw new TypeError('Expected a URL string');

  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== allowedOrigin || url.username || url.password) {
    throw new TypeError('Request URL is not allowed');
  }

  return needle.get(url.href, {
    agent,
    follow_max: 0,
    proxy: null,
    use_proxy_from_env_var: false,
    rejectUnauthorized: true,
  });
}
