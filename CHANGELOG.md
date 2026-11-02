# Changelog

## 0.1.1

- Container image on GHCR, icon, README badges, GitHub release created by the publish workflow.

## 0.1.0

- Initial release: OSPFv2 (RFC 2328) lab test peer over raw IP protocol 89.
- Packet builders and parser for Hello, DBD, LSR, LSU, LSAck; LSA builder for Router, Network, Summary and External LSAs.
- Sessions with neighbor state machine, DR/BDR election, LSDB, SPF, null/simple/MD5 authentication.
- Fault injection: suppressed hellos, timer/MTU mismatch, corrupt checksums, raw message injection.
- Reset-OspfNeighbor: integration point to force a neighbor Down immediately (e.g. on BFD Down), with optional hello hold-down.
- Generic `New-Packet`, `New-PacketField`, `Format-Packet` helpers.
