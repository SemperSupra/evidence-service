# OpenBao Raft snapshot: single-node rollback RDT&E

This independent workcell exercises an **ephemeral, single-node OpenBao
integrated Raft storage instance** using only newly generated owned-test tokens
and synthetic packet/derived/keylog artifacts. The public Actions runner
stores the snapshot privately and destroys the container, Docker volume,
snapshot, unseal share and test tokens on exit. Nothing is uploaded.

Procedure: initialize and unseal an isolated Raft server; create a derived,
nonexportable Transit test key and a restricted worker token; seal a signed
three-artifact synthetic bundle; save a native Raft snapshot; create an
additional post-snapshot test key; restore the snapshot and require that
the later key disappears. Then restart the OpenBao container with its
retained Raft volume, require sealed-before-unseal, and recover the **same**
previously signed bundle through the original restricted worker token from a
fresh Go process. The independently trusted signer public key is kept
outside the bundle.

Acceptance depends on two exact-head workflows: the regular five-job public
Go/packet qualification and the separate real isolated Raft snapshot run.
Any failure keeps the PR open. The original snapshot is sensitive key custody
even for synthetic fixtures: never publish it in Git or CI artifacts.

**Explicitly unqualified:** fresh-node or cross-host disaster recovery,
restoring the snapshot into an independently initialized cluster, backup
transport/storage retention, audit-chain integrity, seal-share escrow,
key retirement, Raft multi-node quorum/HA, Windows ACL, immutable artifact
storage, trusted identity and production key logging. This source-safe RDT&E
does not grant agents the ability to retrieve raw keys or authorize replay.

References: official OpenBao
[Raft integrated storage](https://openbao.org/docs/configuration/storage/raft/)
and [snapshot save/restore](https://openbao.org/docs/next/commands/operator/raft/).
Authority: [Evidence Service DLE #1](https://github.com/SemperSupra/evidence-service/issues/1).
