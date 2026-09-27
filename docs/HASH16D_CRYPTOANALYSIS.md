# Криптографический аудит восстановленного Hash16D

## Provenance

Восстановлен из исходного пользовательского архива:

`files (6).zip -> SYNERGY_ORCH.zip -> SYNERGY_ORCH/l1/hash16d.py`

Исходный файл:
- 9,611 байт;
- 250 строк с учётом завершающей пустой строки;
- SHA-256: `f0e57cd160d537e06abecb665b10ad37cd38c8919a1d2f1e336d8f661c80a3a6`;
- persona по умолчанию: `SINERGY_16D_v3`.

## Фактическая конструкция

Hash16D вычисляет 16 детерминированных 32-байтовых ветвей, XOR-ит их и затем применяет SHA3-256.

Финальная функция:

`SHA3-256(D01 XOR D02 XOR ... XOR D16)`

Поэтому это экспериментальный **256-битный hash-combiner**, а не KEM, цифровая подпись или ratchet.

## Классификация ветвей

| D | Имя в legacy-коде | Фактическая операция | Статус |
|---|---|---|---|
| D01 | SHA3-256 | SHA3-256 | стандартный hash |
| D02 | SHA3-512 | первые 32 байта SHA3-512 | hash-derived |
| D03 | BLAKE2b | BLAKE2b-256 | стандартный hash |
| D04 | BLAKE2s | BLAKE2s-256 | стандартный hash |
| D05 | SHAKE-256 | SHAKE-256 XOF, 32 B | стандартный XOF |
| D06 | SHA-512/256 | XOR половин SHA-512 | кастомная компрессия, не SHA-512/256 standard |
| D07 | HMAC-SHA256 | HMAC с публичной persona | domain-separated hash-like branch |
| D08 | memory-hard | scrypt / fast SHA3 fallback | стандартный KDF только в full mode |
| D09 | Ring-LWE | детерминированная polynomial convolution mod 3329 | **не Ring-LWE KEM/assumption** |
| D10 | Isogeny | 16 итераций x²+1 mod 2^127-1 | **не isogeny cryptography** |
| D11 | Merkle | 4-leaf SHA3 Merkle tree | Merkle commitment |
| D12 | SPHINCS+ | 8 раундов hash chaining | **не SPHINCS+ signature** |
| D13 | NTRU | детерминированная cyclic convolution mod 257 | **не NTRU cryptosystem** |
| D14 | XOR-fold | XOR половин SHA-512 | hash-derived |
| D15 | FNV1a-128 | FNV1a-128 padded to 32 B | non-cryptographic component |
| D16 | Pedersen | modular exponent product mod 2^255-19 | **не стандартный EC Pedersen commitment** |

## Security conclusion

Старое утверждение `2^4096` не следует из кода.

Причины:

1. финальный output имеет 256 бит;
2. независимые 256-битные ветви, сведённые XOR и затем SHA3-256, не складывают security bits арифметически;
3. несколько ветвей названы в честь PQC-конструкций, но не реализуют соответствующие стандарты/assumptions;
4. публичная persona HMAC не является секретным ключом;
5. FNV1a не является криптографическим hash.

Для идеального 256-битного hash generic bounds определяются прежде всего размером выхода и свойствами финального SHA3-256, а не числом "измерений".

## Post-quantum status

Hash16D может использоваться только как experimental supplemental commitment.

Он **не должен** заменять:
- ML-KEM-1024;
- ML-DSA-87;
- SLH-DSA-SHAKE-256s;
- SHA3/SHAKE/HKDF/AEAD production primitives.

## PI finding

Полный форензический scan исходных пакетов `files.zip` и `files (1)..(7).zip` не нашёл отдельной криптографической реализации, использующей число π.

Найденные `math.pi` относятся к UI-графике, синусоидальным моделям газа и Gaussian/RL формулам, а не к криптографии.

Следовательно:
- recovered Hash16D != PI-PQ;
- историческая PI-PQ линия пока остаётся без восстановленного исходника;
- нельзя приписывать Hash16D свойства "криптографии на числе π".
