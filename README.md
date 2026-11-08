# Mail Evidence Kit

Triage a saved .eml message offline. Compare the visible sender and reply address, inspect HTML link destinations, and fingerprint attachments without opening them.

## Reproduce the case

Requires Python 3.11+. All examples use synthetic data and run locally with the standard library. Run from the repository root.

```sh
python triage.py examples/invoice.eml
```

The invoice claims to come from billing.example but replies go to payments.example. The displayed link names billing.example while its destination is portal.example. The JSON report also contains a SHA-256 digest for the synthetic attachment, ready to compare with another sample.

## Design and limits

Python’s MIME parser decodes transfer encodings before hashing. An HTML parser extracts anchor text, and URL parsing compares exact normalized hostnames. Host mismatches are investigation leads: mailing lists, legitimate redirects and aliases can generate them. Sender headers are unverified. Only HTTP(S) anchors whose visible labels are absolute URLs are compared. The 5 MiB limit is applied before parsing. No DNS, reputation service or attachment execution is involved.

## Verification

```sh
python -m unittest discover -s tests -v
```

Tests cover base64 attachment hashing, nested anchor text, reply-domain disagreement, same-host links and a missing Reply-To header.
