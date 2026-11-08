import argparse
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import urlsplit

LIMIT = 5 * 1024 * 1024


def host(url):
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme in ("http", "https") and parsed.hostname:
            return parsed.hostname.rstrip(".").lower()
    except ValueError:
        pass
    return None


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.target = None
        self.label = []
        self.mismatches = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.target = host(dict(attrs).get("href") or "")
            self.label = []

    def handle_data(self, data):
        if self.target:
            self.label.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.target:
            shown = host("".join(self.label))
            if shown and shown != self.target:
                self.mismatches.append(dict(displayed_host=shown, destination_host=self.target))
            self.target = None


def domain(message, name):
    address = parseaddr(str(message.get(name, "")))[1]
    return address.rsplit("@", 1)[1].lower() if "@" in address else None


def analyze(raw):
    if len(raw) > LIMIT:
        raise ValueError("message exceeds 5 MiB")
    mail = BytesParser(policy=policy.default).parsebytes(raw)
    sender, reply = domain(mail, "From"), domain(mail, "Reply-To")
    attachments, links = [], []
    for part in mail.walk():
        if part.is_multipart():
            continue
        if part.get_filename() or part.get_content_disposition() == "attachment":
            body = part.get_payload(decode=True) or b""
            attachments.append(dict(name=part.get_filename(), size=len(body), sha256=sha256(body).hexdigest()))
        elif part.get_content_type() == "text/html":
            parser = Links()
            parser.feed(part.get_content())
            parser.close()
            links.extend(parser.mismatches)
    return dict(sender_domain=sender, reply_domain=reply,
                reply_mismatch=bool(sender and reply and sender != reply),
                link_mismatches=links, attachments=attachments)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description="Extract offline email triage evidence")
    cli.add_argument("message", type=Path)
    args = cli.parse_args()
    try:
        with args.message.open("rb") as source:
            print(json.dumps(analyze(source.read(LIMIT + 1)), indent=2))
    except (OSError, ValueError, LookupError) as exc:
        cli.exit(2, f"Could not parse message: {exc}\n")
