# True Protection - Community YARA Rules

Community-contributed YARA detection rules for [True Protection by Jag](https://tpjsecurity.com).

## How It Works

1. Submit your YARA rules via pull request
2. Our team reviews and tests the rules against clean and malicious corpora
3. Approved rules are merged and pushed to all True Protection users via auto-update
4. Your contribution helps protect millions of users worldwide

## Submitting Rules

### Rule Format

```yara
rule ExampleMalware : trojan
{
    meta:
        author = "Your Name"
        description = "Detects Example Trojan variant"
        date = "2026-03-28"
        reference = "https://example.com/analysis"
        severity = "high"
        hash = "abc123..."

    strings:
        $s1 = { 4D 5A 90 00 }
        $s2 = "malicious_string"

    condition:
        uint16(0) == 0x5A4D and all of them
}
```

### Requirements

- Rules must include `meta` section with author, description, and date
- Rules must not trigger false positives on common clean software
- Include at least one sample hash when possible
- One rule per file, named descriptively (e.g., `trojan_example_variant_a.yar`)

### Directory Structure

```
community/
  ├── trojan/       # Trojan detection rules
  ├── ransomware/   # Ransomware detection rules
  ├── rootkit/      # Rootkit detection rules
  ├── pup/          # Potentially unwanted programs
  ├── exploit/      # Exploit detection rules
  └── misc/         # Other malware categories
```

## License

All community-contributed rules are licensed under the [MIT License](LICENSE).

## Code of Conduct

Be respectful. Don't submit rules that target legitimate software. Don't submit rules derived from proprietary threat intelligence without permission.

---

Powered by [True Protection by Jag](https://tpjsecurity.com) | Copyright 2026 Jag Journey, LLC
