# Trademark policy

The **midwatch** name and logo and the **SecurQbit** name and logo are
trademarks of SecurQbit. The [MPL-2.0](LICENSE) licence covers the *code*; it
does not grant any right to use these marks (see MPL-2.0 §3.5).

This policy exists for one reason. midwatch tells people whether their network
can be trusted, and a report is only worth reading if you know who wrote the
tool that produced it. If anyone could ship modified detection logic under the
name "midwatch", the name would stop meaning anything — and the person harmed
would be the user reading a verdict they had no reason to doubt.

## What you may do without asking

- Use, modify, redistribute and sell the software under the terms of the MPL.
- Say that your product "uses midwatch", "is built on midwatch", or "is
  compatible with midwatch", as long as it is accurate and does not suggest
  that SecurQbit produced, endorsed or supports your product.
- Use the name in articles, talks, comparisons, reviews and documentation.
- Keep the name in an **unmodified** redistribution — packaging midwatch for
  Homebrew, Debian, Arch, nixpkgs, Alpine or any other distribution is
  explicitly welcome and needs no permission. Patches for packaging, portability
  and platform integration are fine and remain "unmodified" for this purpose.

## What needs a different name

If you distribute a **modified** version — changed detection logic, changed
thresholds, changed findings, changed scoring — call it something else. You do
not need our permission to fork; you need a name that is not ours, so that a
user can tell whose judgement they are reading.

Concretely, do not:

- Use "midwatch" or "SecurQbit" in the name of a fork, product or service.
- Use our logos, or a confusingly similar name or mark.
- Register domains, social accounts, app store listings or package names that
  imply you are us.
- Suggest SecurQbit endorses, sponsors or maintains your version.

Renaming a fork is a small change: the binary name, the module path, and the
`Tool` field in the JSON report.

## Reporting misuse, and asking

Questions and permission requests: **legal@securqbit.com**.
We are happy to say yes to reasonable uses; ask before assuming no.
