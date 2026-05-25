# ChordProtocol

A C implementation of the Chord distributed hash table (DHT) protocol, using Protocol Buffers for message serialization.

## What Is Chord?

Chord is a peer-to-peer lookup protocol that maps keys to nodes in a distributed network. Each node is responsible for a range of keys, and lookups are resolved in O(log N) hops using a **finger table** — a routing structure that enables efficient key lookup across the ring.

## Project Structure

```
ChordProtocol/
├── Makefile          # Build instructions
├── include/          # Header files
├── protobuf/         # Protocol Buffer definitions for messaging
└── src/              # C source files
```

## Getting Started

### Prerequisites

- GCC or Clang
- Protocol Buffers C library (`libprotobuf-c`)

### Build

```bash
make
```

### Run

After building, run the node binary with appropriate arguments (see `src/` for entry point details).

## Tech Stack

- **Language:** C
- **Serialization:** Protocol Buffers
- **Build System:** Make

## Concepts Covered

- Distributed hash tables (DHT)
- Chord ring topology and finger tables
- Consistent hashing
- Node join/leave and key lookup
