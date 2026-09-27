# R3 Real Hardware Transport

## Цель

R3 превращает protocol-only прототип в transport-ready двухузловой radio protocol.

Ключевой барьер: SLH-DSA-SHAKE-256s подпись имеет размер около 29.8 KB, поэтому
полный dual-PQ handshake не помещается в один типичный low-bandwidth radio frame.

## Решение

Добавлен модуль `src/wire.rs`:

- versioned binary wire format;
- строгие максимальные длины каждого поля;
- message type binding;
- SHA-256 root полного wire message;
- fragmentation/reassembly;
- случайный 128-bit message id;
- защита от conflicting duplicate fragments;
- запрет смешивания fragment sets;
- ограничение количества фрагментов и общего размера.

Формат физического фрагмента:

```text
SPQF
version
message_id[16]
fragment_index u32
fragment_total u32
wire_message_sha256[32]
payload...
```

Размер заголовка: 61 байт.

## Двухузловой protocol flow

```text
NODE A                         NODE B
  |                              |
  | fragmented ClientHello       |
  |----------------------------->|
  |                              |
  | fragmented ServerHello       |
  | + ML-DSA + SLH-DSA           |
  |<-----------------------------|
  |                              |
  | fragmented ClientFinish      |
  | + second ML-KEM ct           |
  | + ML-DSA + SLH-DSA           |
  |----------------------------->|
  |                              |
  | independent HKDF traffic keys|
  |                              |
  | encrypted application frame  |
  |----------------------------->|
  |             ACK              |
  |<-----------------------------|
```

Unit test `two_nodes_complete_full_pq_handshake_over_tiny_mtu` intentionally
uses MTU=128 bytes, forcing the large PQ signatures through the fragmentation layer.

## Serial/UART/LoRa adapter

Feature:

```bash
cargo build --features serial --bin synergy-pq-radio-serial-node
```

Example with two virtual or physical serial ports:

Terminal A:

```bash
cargo run --features serial --bin synergy-pq-radio-serial-node -- \
  server /dev/ttyUSB0 115200
```

Terminal B:

```bash
cargo run --features serial --bin synergy-pq-radio-serial-node -- \
  client /dev/ttyUSB1 115200 "HELLO OVER REAL RADIO"
```

Windows example:

```powershell
cargo run --features serial --bin synergy-pq-radio-serial-node -- server COM5 115200
cargo run --features serial --bin synergy-pq-radio-serial-node -- client COM6 115200 "HELLO"
```

The attached LoRa/FSK/SDR modem must already be configured to expose a reliable
transparent byte stream. RF frequency, coding rate, spreading factor, TX power,
regulatory limits and modem-specific packetization remain hardware configuration.

## What this proves and does not prove

The code proves a deterministic two-node PQ protocol can traverse a small-MTU byte transport.

It does **not** prove RF propagation until two real modems physically exchange bytes.
A physical RF GREEN requires captured device identifiers, modem configuration,
packet counters, transcript root and successful bidirectional payload evidence.
