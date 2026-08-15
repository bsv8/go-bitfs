---
id: sdk-api-framework-design
title: BitFS SDK API framework
---

# BitFS SDK API framework

go-bitfs is the executable protocol specification for 001–007. It owns
deterministic Build/Read/Verify behavior, protocol calculations, state
transitions, and the fixed MasterSeed and MultisigPool implementations.

Applications provide only infrastructure: `Signer`, persistence, content
source/sink, and narrow BSV acceptance backends. Peer transport is completely
outside the SDK. Transaction construction, verification, pricing, and expiry
rules remain fixed core behavior.
