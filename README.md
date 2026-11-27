# prakash

Inspect a server's TLS certificate, protocol, and version support from the terminal.

## The name

*prakāśa* (प्रकाश) is Sanskrit for "light" or "the act of making visible".
TLS is normally opaque; prakash shines a light on what a server actually
presents.

## Features

- Shows the full certificate **chain**: subject, issuer, and key per cert
- Leaf **validity window**, **days-to-expiry**, and **Subject Alternative Names**
- **Key type and size** (RSA bit length, EC named curve, Ed25519) parsed straight
  from the certificate DER - no OpenSSL command or third-party library
- **Negotiated protocol and cipher**
- Probes which **TLS versions** (1.0, 1.1, 1.2, 1.3) the server will accept,
  each via its own handshake
- **Warns** when the leaf expires under N days, when a weak RSA key is used, or
  when deprecated TLS 1.0/1.1 is still accepted
- **Batch mode** over a host list - ideal for expiry monitoring in cron
- `--json` output, optional ANSI color (`--no-color`, honours `NO_COLOR`)
- Standard library only

## Install

Requires Python 3.10+. The full certificate chain is shown on Python 3.13+
(which exposes the unverified chain); on older versions the leaf is shown.

```sh
git clone https://github.com/Linuxboii/prakash
cd prakash
pip install .            # installs the `prakash` command
```

Or run from source:

```sh
python -m prakash --help
```

## Usage

```
prakash [flags] <host[:port]> [host...]

  -f, --file       file of hosts (one per line) for batch mode
  -p, --port       default port (443)
  -t, --timeout    timeout seconds (default 7)
  -w, --warn-days  warn if expiry is under N days (default 30)
      --no-probe   skip the per-version TLS handshake probes
      --json       emit JSON
      --no-color   disable ANSI color
```

### Inspect a host

```
$ prakash example.com
example.com:443
  negotiated : TLSv1.3  TLS_AES_256_GCM_SHA384 (256-bit)
  leaf   subject: example.com
         issuer : Cloudflare TLS Issuing ECC CA 3
         key    : EC 256-bit (P-256 (secp256r1))
         valid  : 2026-11-24T23:48:34+00:00  ->  2027-02-22T23:53:08+00:00
         expiry : 87 day(s)
         SANs   : example.com, *.example.com
  ca[1]  subject: Cloudflare TLS Issuing ECC CA 3
         issuer : SSL.com TLS Transit ECC CA R2
         key    : EC 256-bit (P-256 (secp256r1))
  versions   : TLSv1.0 no  TLSv1.1 no  TLSv1.2 yes  TLSv1.3 yes
```

### Batch expiry monitoring

```
$ prakash --file hosts.txt --warn-days 21 --no-probe
```

`hosts.txt` holds one `host` or `host:port` per line (`#` comments allowed).
The process exits `1` if any host failed or produced a warning, so it fits
cleanly into a monitoring job.

### JSON

```
$ prakash example.com:443 --json
{
  "host": "example.com",
  "port": 443,
  "protocol": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "chain": [ { "subject": "example.com", "days_left": 87, "key_type": "EC", ... } ],
  "supported_versions": { "TLSv1.2": true, "TLSv1.3": true },
  "warnings": []
}
```

## A note on certificate verification

prakash deliberately connects **without** trust verification. That is
required: the whole point is to inspect certificates that may be expired,
self-signed, or otherwise untrusted, and a verifying client would simply refuse
to complete the handshake. The tool reports what it sees; it does not establish
a secure channel or send any data over the connection.

## Scope

Use only against hosts you own or are explicitly authorized to assess.

## Testing

```sh
python -m unittest
```

The certificate-parsing helpers (`der`, `certinfo`) are unit-tested against
crafted DER bytes, so the tests run fully offline.

## License

MIT - see [LICENSE](LICENSE).
