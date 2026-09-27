# R3 PI-PQ Forensics

Дата: 2026-09-28

## Цель

Найти именно историческую proprietary PI-based криптографию SYNERGY, не подменяя её
восстановленным Hash16D и не придумывая алгоритм заново.

## Проверенные источники

### 1. GitHub: canonical и historical branches

Проверены:
- `main`;
- `feat/protocol-convergence-pi-pq-evm-syna-v1-20260925`;
- PI-PQ related commits;
- P4 evidence bundle и `14_pi_pq.log`.

Ключевой commit:

`7831dfd980ac35a5b89c1660b099d3b85e357c46`
— `feat(pi-pq): add fail-closed provenance evidence lane`.

Он **добавляет** `src/pi_pq.rs` с нуля: 86 additions, 0 deletions.
Сам файл прямо говорит, что исторический PI-based primitive НЕ реализован и не
должен быть придуман без восстановления точного исходника.

Предшествующий convergence document:

`b7ed530b1264692697c0250f01b3318981395462`

тоже определяет Gate P1 как будущую задачу:
- locate exact source;
- hash-pin it;
- write specification/vectors;
- classify primitive;
- keep non-authoritative.

Вывод: ветка protocol-convergence **не содержит скрытой реализации PI-PQ**.
Она содержит только интерфейс/evidence shell.

### 2. R2 historical source archives

Полностью проверены:
- `files.zip`;
- `files (1).zip`;
- ...;
- `files (7).zip`;
- вложенный `SYNERGY_ORCH.zip`.

Восстановлен точный:
`SYNERGY_ORCH/l1/hash16d.py`,
SHA-256:
`f0e57cd160d537e06abecb665b10ad37cd38c8919a1d2f1e336d8f661c80a3a6`.

В нём отсутствуют:
- digits of π;
- `math.pi`;
- PI-derived key stream;
- PI-derived KDF;
- PI ratchet;
- PI nonce schedule.

Поэтому:
`Hash16D != PI-PQ`.

### 3. Library / project files

Искались:
- PI-PQ;
- pi_pq;
- "криптография на числе Пи";
- "криптография на числе PI";
- pi-derived;
- PI based cryptography;
- time-ratchet;
- digit-derived key material.

Найдены только общие заявления о post-quantum cryptography и поздний
fail-closed PI-PQ integration shell. Точного алгоритма, формулы, KAT или исходника нет.

### 4. Prior conversations / project context

Исторический контекст подтверждает, что пользователь называл собственный алгоритм
"на числе PI", но доступная история не содержит реализации, формул, точного имени
файла или primitive class.

### 5. Google Drive

Выполнен поиск по PI-PQ/pi_pq/PI based cryptography/PI ratchet и связанным ключам.
Точного исходника или спецификации PI-PQ не обнаружено. Большая часть совпадений
относится к общему post-quantum контенту или посторонним материалам.

## Доказательный итог

На текущем наборе доступных источников:

- существование исторической PI-based research line: **подтверждено описаниями**;
- exact source: **не восстановлен**;
- exact formula: **не восстановлена**;
- primitive class: **неизвестен**;
- KAT/vector suite: **нет**;
- production authority: **запрещена fail-closed политикой**.

## Следующая зона поиска

Дальше имеет смысл искать не в уже просмотренных GitHub/Library bundles, а в:
1. старых локальных дисках/ПК;
2. архивных ZIP/RAR/7z вне пакетов `files (1)..(7)`;
3. старых Downloads/Desktop/Documents;
4. Telegram/WhatsApp exported files;
5. старых Git working trees без push;
6. резервных копиях облаков;
7. исходных чат-экспортах, если там был вставлен код целиком.

До нахождения реального исходника PI-PQ остаётся строго
`EXPERIMENTAL_NON_AUTHORITATIVE`.
