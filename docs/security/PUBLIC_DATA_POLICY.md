# Public Data Policy

This public repository follows a synthetic-data-first policy.

Real credentials, tokens, private keys, personal data, confidential
documents, customer evidence, internal identifiers, and sensitive
production logs must not be committed.

Demo and test material must be synthetic by construction or explicitly
public.

Reserved documentation ranges and domains should be preferred for
examples, including TEST-NET addresses and example domains.

If the publication status of any artifact is uncertain, treat it as
sensitive and do not commit it.

Security review is defense in depth. A clean secret scan alone is not
authorization to publish data.

Repository publication requires, where applicable:

- synthetic/public data review;
- automated secret scanning;
- tests against accidental leakage;
- staged diff inspection;
- security/adversarial review;
- clean global quality gates.

Original evidence from real investigations must never be copied into
this public repository.
