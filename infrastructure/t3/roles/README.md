# Closed role receipts and aggregation

This is synthetic-tested infrastructure, not an execution grant. `Aggregator.finalize` always rejects terminal PASS signing until separately reviewed execution authority is wired in. No research subjects, scientific seeds, fixture histories, private evidence or workflow dispatches are embedded here.

The private owner injects the exact pinned receipt schema, signer keys, domains and immutable permit bindings. The receipt verifier checks the complete schema, real Ed25519 signature, source/environment/authority, role, subject, permit and job/process identity fields. An absent case/control binding fails even when the signature is otherwise valid.

A Micro registry binding must contain exactly `registry_sha256`, `fixture_sha256`, `schedule_sha256`, `life_cycles`, `structural_direct_processings`, `direct_batch_calls`, with lowercase SHA256 strings and nonnegative integer counts. Empty/partial bindings are rejected. These keys match accepted receipt fields; the private receipt schema supplies additional exact counts and closed subject variants. Immutable audit manifests must bind their producer receipt digest and exact gate/control assertion sets. Shape validity and synthetic tests are not evidence that scientific assertions were measured.

`artifacts.py::EvidenceAudit` מחבר קבלת יצרן מאומתת אל `SignedInventoryReader`, אל מעריך פרטי ואל מניפסט בדיקה חתום באחסון לפי VersionId. כל תוצאה חסרה/חלקית או errors/failures/skips שאינם אפס נסגרת בכשל. זה אינו מחשב סמנטיקה במקום מעריך המחקר ואינו מעניק סמכות להפיק PASS כולל; `Aggregator.finalize` עדיין חסום ללא סמכות ביצוע מאושרת. בדיקת החיבור החדשה קוראת בתים מוצפנים וחתומים בפועל ושומרת את מניפסט הבדיקה באחסון המקומי; התוכן סינתטי ואינו ניסוי T3.

Privileged ReceiptAuthority and CampaignRegistry now own recursively immutable
snapshots (MappingProxyType, tuples/frozensets). Caller aliases and ordinary or
base-dict key substitution cannot change signers, permit subjects, domains or
gate assertions after construction. This is configuration ownership, not a
Python sandbox for arbitrary code already executing in the trusted process.
