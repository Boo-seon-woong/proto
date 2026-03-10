SKILL: Prototype Implementation for TDX-Compatible Client-Centric KVS with Cache-Prime Snapshot

1. System Goal

This prototype implements a modified client-centric distributed key-value store inspired by FUSEE, adapted for a confidential computing environment (e.g., Intel TDX).

Key design objectives:

1. Preserve client-centric RDMA execution for the majority of operations.
2. Avoid frequent writes to private memory to prevent bottlenecks.
3. Use shared memory only for ciphertext storage.
4. Maintain correctness of snapshot-based CAS consensus.
5. Introduce a cache-prime table that acts as the authoritative commit pointer table for hot data.

The system separates responsibilities into:

- Private Memory (MN TDX private memory)
- Shared Memory (RDMA-accessible ciphertext region)
- Cache
- Cache-Prime Table


2. Memory Layout

2.1 Private Memory (TDX private)

Private memory acts as the backing store.

It contains:

- Cold KV values
- Metadata required for recovery
- Eviction flush targets

Private memory is NOT updated on every write/update.

Updates occur only during:

- Cache miss fetch
- Cache eviction flush

All values are stored as ciphertext.


2.2 Shared Memory

All shared memory contents are ciphertext.

Accessible through RDMA.

Shared memory contains:

1. Cache slots
2. Cache-Prime Table

Shared memory never stores plaintext.

Decryption keys exist only at CN (client nodes).


3. Core Data Structures

3.1 Cache Slot

Cache stores ciphertext KV bodies.

Each slot:

struct CacheSlot {
    slot_id
    ciphertext_value
    nonce
    tag
    epoch
}

epoch prevents ABA problems when slots are reused.

Slots are append-allocated.

Slots may be reused only after epoch increment.


3.2 Cache-Prime Table

Cache-Prime Table is the authoritative expected pointer table.

It functions as the commit pointer layer.

Each key has a single entry.

struct PrimeEntry {
    key
    addr
    epoch
    private_addr
    valid
}

This table defines the current committed version of each key.

Snapshot consensus uses this table as the expected state.

Cache slots themselves are NOT authoritative.


4. Authoritative State

Authoritative value location for a key is determined ONLY by:

CachePrimeTable[key].addr
CachePrimeTable[key].epoch

The value body is read from:

cache_slot = addr

Private memory is used only if the key is not present in CachePrimeTable.


5. Encryption Model

All shared memory data are ciphertext.

Encryption properties:

- Encryption key exists only at CN
- MN cannot decrypt
- CAS operations compare ciphertext pointers only

Integrity is guaranteed by authenticated encryption (e.g., AES-GCM).


6. Operation Flow

6.1 WRITE / UPDATE (Cache Hit)

This is the fast path.

No MN CPU involvement.

Steps:

1. CN allocates a new cache slot.
2. CN encrypts value.
3. Write ciphertext into cache slot.
4. Perform CAS on Cache-Prime Table entry:

expected = (old_addr, old_epoch)

new = (new_addr, new_epoch)

5. If CAS succeeds → write complete.
6. Workload completes entirely via RDMA.

No private memory access occurs.


6.2 WRITE / UPDATE (Cache Miss)

Cache miss occurs if key is not present in CachePrimeTable.

Steps:

1. RDMA operation aborted.
2. CN sends request to MN CPU.
3. MN reads ciphertext value from private memory.
4. Value returned to CN.
5. CN inserts value into cache slot.
6. Create CachePrimeTable entry.

Result:

Key becomes cache-resident.

Subsequent updates follow fast RDMA path.


7. READ Operation

Read order:

1. Lookup CachePrimeTable
2. If entry exists:
       read cache slot
3. If entry does not exist:
       request MN CPU
       read private memory
       optionally populate cache

Consistency rule:

entry1 = read prime table
value = read cache slot
entry2 = read prime table

if entry1 != entry2
    retry

This double-check guarantees snapshot correctness.


8. Snapshot Consensus

Snapshot expected value is derived from:

(expected_addr, expected_epoch)

not from the value itself.

CAS rule:

CAS(
    PrimeEntry[key],
    expected=(addr, epoch),
    new=(addr_new, epoch_new)
)

This preserves client-centric CAS semantics.


9. Cache Eviction

When cache capacity is exceeded:

1. Choose eviction victim.
2. Read victim PrimeEntry.
3. Fetch ciphertext from cache slot.
4. Write ciphertext to private memory.
5. Update private backing address.
6. Remove PrimeEntry entry.

Eviction uses PrimeEntry as the authoritative pointer.

Cache slot content alone must never be trusted.


10. Delete Operation

Delete is implemented as a tombstone write.

Steps:

1. allocate cache slot
2. write tombstone marker
3. CAS update PrimeEntry

PrimeEntry.addr = tombstone_slot

During eviction:

- private value is deleted
- PrimeEntry removed

Reads encountering tombstone return NOT_FOUND.


11. Replication

Replication strategy may follow FUSEE.

Client selects replica MNs.

Typical approach:

replica = hash(key) % N

Client performs CAS on each replica's CachePrimeTable.

Consensus rule identical to FUSEE snapshot consensus.


12. Failure Recovery

Private memory stores cold copies.

During recovery:

1. rebuild cache lazily
2. repopulate PrimeEntry when keys become hot
3. private memory acts as ground truth for cold keys