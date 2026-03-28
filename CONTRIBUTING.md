# Contributing to True Protection

## What You Can Contribute

True Protection's core engine is proprietary. Two components are open source:

| Component | License | Location |
|-----------|---------|----------|
| Community YARA rules | MIT | community-yara-rules/ |
| Browser extension | MIT | browser-extension/ |

## YARA Rules

1. Fork this repo
2. Create branch: `yara/descriptive-name`
3. Add rule to appropriate category folder
4. Test against clean files to avoid false positives
5. Open a PR with the YARA submission template

Requirements: author, description, date, reference, severity metadata. At least one sample hash.

## Browser Extension

1. Fork and clone
2. Load unpacked in Chrome/Edge: `chrome://extensions` > Developer mode > Load unpacked
3. Make changes and test on Chrome + Firefox
4. Open a PR with clear description

## Bug Reports

Use the bug report template. Include: version, OS, steps to reproduce, expected vs actual behavior.

## Feature Requests

Use the feature request template. Search existing requests first.

## Security Issues

Do NOT open public issues. Email security@jagjourney.com. See SECURITY.md.

---

Jag Journey, LLC | [tpjsecurity.com](https://tpjsecurity.com)
