# SYNERGY Post-Quantum Radio

Рабочий исследовательский прототип защищённого радиопротокола SYNERGY с обязательной стандартизованной постквантовой криптографией и отдельным интерфейсом для квантовой телепортации.

## Реализовано

- ML-KEM-1024 для установления секретов;
- два независимых ML-KEM направления в handshake;
- ML-DSA-87 + SLH-DSA-SHAKE-256s как обязательная dual-PQ аутентификация;
- transcript binding и domain separation;
- HKDF-SHA256 с разными directional traffic keys;
- ChaCha20-Poly1305 для radio frames;
- strict sequence/replay gate;
- абстракция RadioLink и loopback backend;
- QuantumTeleportationBackend;
- Bell-state teleportation simulator со всеми 4 исходами Bell-измерения;
- cryptographic binding teleportation receipt в PQ handshake;
- PI-PQ evidence lane в fail-closed режиме;
- demo и тесты.

## Важная физическая граница

Симулятор не выдаётся за физическое квантовое оборудование. Физическая квантовая телепортация требует заранее распределённой запутанности и классической передачи результатов Bell-измерения. Она не заменяет радио/классический канал и не обеспечивает сверхсветовую передачу.

SimulatedTeleportationBackend всегда имеет режим Simulation. Его receipt криптографически привязывается к handshake, но никогда не повышает статус до доказанной физической телепортации.

Для реального QPU/quantum-network оборудования нужно реализовать trait QuantumTeleportationBackend и выдавать Hardware receipt только из измеряемого физического experiment pipeline.

## Собственная PI-PQ криптография

Аудит 75 репозиториев обнаружил текущую fail-closed линию в Shtenco/synergy_ai_blockchain/src/pi_pq.rs. Каноническая документация указывает исторический кандидат SYNERGY_ORCH/l1/hash16d.py (~9.4 KB, пять исторических копий), но сам исходник отсутствует в текущем main.

До восстановления алгоритма PI-PQ не является trust root и не заменяет standards-based PQC.

Подробности: docs/PQ_REPOSITORY_AUDIT.md

## Handshake

~~~text
Alice                                      Bob
  |                                         |
  | ClientHello                             |
  | session_id, epoch, ML-KEM pk_A          |
  | PQ identity, radio caps                 |
  | teleportation_root?, pi_pq_root?        |
  |---------------------------------------->|
  |                                         |
  |                encapsulate(pk_A)        |
  |                fresh ML-KEM pk_B        |
  |                dual-PQ sign transcript  |
  |<----------------------------------------|
  | ServerHello + ct_B->A + dual PQ sig     |
  |                                         |
  | verify both PQ signatures               |
  | decapsulate ct_B->A                      |
  | encapsulate(pk_B)                        |
  | dual-PQ sign ClientFinish               |
  |---------------------------------------->|
  | ClientFinish + ct_A->B + dual PQ sig    |
  |                                         |
  | HKDF -> independent C2S and S2C keys    |
  |                                         |
  | ChaCha20-Poly1305 protected frames      |
  |<=======================================>|
~~~

## Запуск

Требуется Rust 1.85+.

~~~bash
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo run --bin synergy-pq-radio-demo
~~~

## Физическое радио

Протокол не привязан к конкретному PHY. Trait RadioLink можно реализовать для LoRa/raw modem, SDR/USRP, UART modem, HF/VHF/UHF data modem, satellite modem или FPGA radio.

## Статус безопасности

PROTOTYPE / RESEARCH.

Код не проходил независимый криптографический аудит. Его нельзя считать production/safety-critical/military/emergency готовым без отдельного review, hardware key custody и испытаний конкретного radio/QPU backend.
## R2: восстановление исторической криптографии

R2 forensic recovery завершил восстановление оригинального `SYNERGY_ORCH/l1/hash16d.py` из исходного пользовательского пакета `files (6).zip -> SYNERGY_ORCH.zip`.

- recovered source SHA-256: `f0e57cd160d537e06abecb665b10ad37cd38c8919a1d2f1e336d8f661c80a3a6`;
- размер: 9 611 байт;
- persona исходника: `SINERGY_16D_v3`;
- исходник сохранён в `legacy/recovered/SYNERGY_ORCH/l1/hash16d.py`;
- добавлены fast/full KAT vectors и `tests/hash16d_kat.py`.

Криптоанализ показал, что Hash16D - экспериментальный 256-битный hash-combiner. Он не является KEM, подписью или ratchet и не даёт обоснования старому security claim `2^4096`. Несколько legacy-ветвей носят названия Ring-LWE, isogeny, SPHINCS+, NTRU и Pedersen, но код не является стандартными реализациями этих конструкций.

Отдельно проверены исторические пакеты `files.zip` и `files (1)..(7).zip`: криптографической реализации на числе π там не найдено. Поэтому `Hash16D != PI-PQ`; PI-PQ остаётся отдельной невосстановленной исследовательской линией.

## Physical / hardware backends

- `StreamRadio<T>` добавляет реальный length-prefixed byte-stream transport для UART/USB serial, SDR-daemon socket wrappers, virtual COM и vendor SDK adapters.
- `HardwareQuantumDriver` + `AttestedHardwareTeleportationBackend<D>` задают границу реального QPU/quantum-network backend.
- hardware teleportation receipt обязан иметь ненулевой `hardware_attestation_root`; simulation receipt не имеет права содержать hardware attestation.

Подробности: `docs/HASH16D_RECOVERY_PROVENANCE.md` и `docs/HASH16D_CRYPTOANALYSIS.md`.