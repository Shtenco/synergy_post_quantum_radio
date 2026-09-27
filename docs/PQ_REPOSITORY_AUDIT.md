# Аудит 75 репозиториев Shtenco: постквантовая и квантовая криптография

Дата: 2026-09-27

Аудит выполнен по всем 75 репозиториям, доступным через подключённый GitHub-аккаунт. Для каждого репозитория было просмотрено рекурсивное Git-дерево; дополнительно выполнены глобальные поиски по ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, SPHINCS, ACVP, FIPS, post-quantum, quantum-safe, PI-PQ и смежным терминам.

## 1. Канонический источник реальной PQ-криптографии

### Shtenco/synergy_ai_blockchain

Найден полноценный standards-based стек:
- ML-KEM-1024;
- ML-DSA-87;
- SLH-DSA-SHAKE-256s;
- HKDF-SHA256;
- ChaCha20-Poly1305;
- dual-PQ authorization;
- transcript/domain binding;
- replay protection;
- opaque/zeroizing secret handles;
- ACVP fixtures для ML-KEM, ML-DSA и SLH-DSA;
- ML-KEM Wycheproof negative subset;
- reference provider;
- executable P4 evidence, включая отдельный PI-PQ test gate.

Ключевые исходники:
- src/pq.rs
- src/pq_reference.rs
- src/network.rs
- src/transport_wire.rs
- src/mesh_transport.rs
- tests/pq_acvp.rs
- tests/vectors/*
- docs/M2_REAL_PQ_CRYPTO_EVIDENCE.md
- docs/PQ_STACK.md

Именно эта реализация выбрана источником криптографической политики для SYNERGY Post-Quantum Radio.

## 2. Собственная PI-PQ схема на числе Pi

В canonical tree найден synergy_ai_blockchain/src/pi_pq.rs. Он намеренно не переизобретает исторический алгоритм и реализует только fail-closed provenance/evidence lane.

CHECKPOINT_P3_2026-09-25.md указывает сильнейший исторический кандидат:
- SYNERGY_ORCH/l1/hash16d.py;
- размер около 9.4 KB;
- пять исторических копий;
- рядом историческая L1-линия ledger.py, node.py, qe_engine.py, sinergy_dex.py.

Сам hash16d.py в текущем main не найден. Поэтому PI-PQ в радио:
- может участвовать как дополнительный domain-separated evidence root;
- не может авторизовать radio session;
- не может заменять ML-KEM/ML-DSA/SLH-DSA;
- должна оставаться experimental до восстановления исходника, спецификации, KAT/vector suite и независимого криптоанализа.

## 3. Другие релевантные репозитории

### Shtenco/synergy_net
В README заявлен post-quantum P2P mesh / authenticated session target. В текущем main реального PQ handshake/provider кода не найдено; это архитектурная линия, а не канонический crypto provider.

### Shtenco/synergy_system
Содержит federation/security roadmap и правило использовать стандартные проверяемые post-quantum primitives.

### Shtenco/synergy_messenger
Есть session crypto / Double Ratchet / OpenMLS-oriented архитектура, но это не источник канонического PQC ядра радио.

### Shtenco/binary_quantum_theory
Содержит квантовую математику и quantum simulation research, но не является реализацией постквантовой криптографии.

### Shtenco/quantum-trading_metatrader5 и quantum-файлы trading-репозиториев
Это квантовые/гибридные вычислительные эксперименты, не PQC.

## 4. Итоговая архитектура радио

1. AUTHORITATIVE CRYPTO: ML-KEM-1024 + ML-DSA-87 + SLH-DSA-SHAKE-256s.
2. QUANTUM TELEPORTATION: отдельный backend interface; Simulation и Hardware различаются явно.
3. PI-PQ: experimental fail-closed evidence lane до восстановления hash16d.py.

Такое разделение не позволяет симуляции или недоказанному proprietary primitive ослабить основной trust root.