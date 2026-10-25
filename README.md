# zerosint

A vibe coded OSINT tool that helps you manage your most common OSINT scans.

You give it whatever you've got (a username, an email, a domain, a phone number) and it runs the usual OSINT tools for you, pivots on what it finds, and ties everything into one scored report instead of leaving you with four separate tool outputs to read through.

It wraps tools you probably already use: Maigret, theHarvester, recon-ng, SpiderFoot, and adds a free breach check on top. If one of those isn't installed, zerosint just skips it and keeps going.

## What it does

- Takes any mix of inputs: username, email, domain, IP, phone.
- Runs the right tool for each one. Username goes to Maigret, domain to theHarvester and recon-ng, email to the breach checks, phone to PhoneInfoga.
- Pivots. Anything it finds becomes a new input, so an email leads to breaches, a domain leads to subdomains and more emails, and so on, up to a depth you set.
- An email's domain is scanned too (`me@acme.io` also scans `acme.io`), except for free webmail providers like gmail.com, outlook.com or yahoo.gr. Scanning those tells you nothing about the target. If you really want one scanned, pass it with `--domain`.
- Scores every finding. If two tools agree on something, its confidence goes up. The further a finding sits from your original input, the lower it gets weighted.
- Writes an HTML report with a findings table and a relationship graph, plus a JSON file and a SQLite database.

## Modules

| Tool | Input | Needs |
|------|-------|-------|
| Maigret | username | maigret installed |
| theHarvester | domain | theHarvester installed |
| recon-ng | domain | recon-cli + one marketplace module (see setup) |
| SpiderFoot | domain, email, ip | sf.py on PATH |
| XposedOrNot | email | nothing, it's free and keyless |
| PhoneInfoga | phone | phoneinfoga binary |
| HIBP | email, username | paid API key, optional |

The XposedOrNot breach check needs no key at all. HIBP is optional and only runs if you set a key.

## Install

```bash
git clone https://github.com/blackowl-zero/zerosint
cd zerosint

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # optional, for API keys
```

### External tools

These run as separate binaries. Install the ones you want:

```bash
pip install maigret theHarvester

# recon-ng ships with zero modules, install the keyless one this tool uses:
recon-cli -C "marketplace install recon/domains-hosts/hackertarget"

# SpiderFoot and PhoneInfoga have their own setup, grab them from their repos.
```

On Windows, run everything inside WSL (Kali works fine). recon-ng and SpiderFoot don't behave on native Windows.

## Usage

```bash
# username + email
python main.py --username someuser --email someone@example.com

# a domain, deeper pivot
python main.py --domain example.com --depth 2

# everything at once
python main.py --username someuser --email a@b.com --domain b.com --phone "+30 ..."

# check if one of your own passwords has leaked
# uses k-anonymity, the password never leaves your machine
python main.py --check-password "mypassword"
```

You get three things out: an HTML report you open in a browser, a JSON dump, and a SQLite db that keeps one scan per run.

## Scope

This is passive recon on public sources only. It reads breach databases, directory tools and search results. It does not test credentials, touch login forms, or do anything active. Run it on yourself or on targets you have written permission to assess. Looking someone up for no reason isn't OSINT, it's just creepy, so don't.

## Why the name

Zero plus OSINT. Also fits the whole blackowl-zero thing.

## License

MIT. Do what you want with it, just don't be stupid with it.
