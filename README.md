# 📡 SYNERGY Post-Quantum Radio

> **Домен:** Infrastructure / Network / Security  
> **Роль:** Исследовательский узел физического radio transport с постквантовой защитой для узлов SYNERGY.  
> **Статус:** 🧱 STUB / R&D — наличие готового UART/LoRa/SDR или PQ hardware backend на main пока не заявляется.  
> **Архитектурный родитель:** [`synergy_meta_os`](https://github.com/Shtenco/synergy_meta_os)

---

## 🎯 Задача репозитория

Исследовательский узел физического radio transport с постквантовой защитой для узлов SYNERGY.

Этот README оформлен по общему стандарту документации SYNERGY: цель → архитектура → границы полномочий → статус доказанности → место в федерации → roadmap.

---

## 🧠 Место в системе

```mermaid
flowchart LR
    SYS[🧭 synergy_system] --> P[synergy_meta_os]
    P --> THIS[📡 synergy_post_quantum_radio]
    THIS --> E[📦 Evidence / artifacts]
    THIS --> I[🔗 Integrations]
```

Архитектурная стрелка означает принадлежность к системному домену. Она **не доказывает** наличие runtime dependency, импорта или готовой интеграции.

---

## 🏗️ Архитектурный контракт

Для перехода из концепта/R&D в подтверждённый компонент репозиторий должен явно описать:

- входные данные и их источник;
- выходные артефакты и формат;
- доверительные границы;
- deterministic validation там, где она возможна;
- конфигурацию и секреты без хранения ключей в README/коде;
- тесты и воспроизводимый запуск;
- ошибки, отказоустойчивость и rollback;
- метрики, по которым можно отличить успех от красивой демонстрации;
- взаимодействие с соседними authority-доменами без дублирования их полномочий.

---

## 🛡️ Authority boundaries

В федерации SYNERGY действуют жёсткие разграничения:

```text
AI recommendation       != authorization
service running         != permission
blockchain record       != accounting truth
mint / rebase           != external profit
UI state                != ledger state
architecture diagram    != tested integration
repository name         != proof of implementation
```

Этот репозиторий должен оставаться в пределах своей предметной области и передавать результаты каноническим владельцам соседних фактов.

---

## 🔬 Статус доказанности

🧱 STUB / R&D — наличие готового UART/LoRa/SDR или PQ hardware backend на main пока не заявляется.

Применяемая шкала:

| Метка | Значение |
|---|---|
| ✅ GREEN | воспроизводимо подтверждено тестами/артефактами |
| 🟡 CANDIDATE | реализация есть, но доказательство неполное |
| 🔬 R&D | экспериментальная линия |
| 🧱 STUB | архитектурный узел без достаточной реализации |
| 🕰️ LEGACY | историческая ветка / provenance |
| ❌ RED | тезис не прошёл проверку |

---

## 🔗 Связанные репозитории

- [`synergy_net`](https://github.com/Shtenco/synergy_net)
- [`synergy_ai_blockchain`](https://github.com/Shtenco/synergy_ai_blockchain)
- [`synergy_turbo_linux`](https://github.com/Shtenco/synergy_turbo_linux)
- [`dlp_solver`](https://github.com/Shtenco/dlp_solver)

Главная карта:
- [🧭 SYNERGY SYSTEM](https://github.com/Shtenco/synergy_system)
- [📚 Атлас всех 75 репозиториев](https://github.com/Shtenco/synergy_system/blob/main/docs/SYNERGY_REPOSITORY_ATLAS.md)
- [🧾 Машиночитаемый registry](https://github.com/Shtenco/synergy_system/blob/main/registry/SYNERGY_REPOSITORIES.json)

---

## 🧪 Критерий перехода в GREEN

Репозиторий нельзя считать зрелым только потому, что появился код. Для GREEN нужны как минимум:

1. воспроизводимый запуск с чистого окружения;
2. version-pinned зависимости;
3. тесты основной функции и негативных сценариев;
4. сохранённые evidence artifacts / metrics;
5. отсутствие скрытого ручного шага в заявленном pipeline;
6. documented failure modes;
7. проверенная интеграционная граница с родительским слоем;
8. README, который не утверждает больше, чем подтверждают артефакты.

---

## 🗺️ Документационный стандарт

По мере развития README должен расширяться предметными разделами, а не общими лозунгами:

```text
проблема
  ↓
теория / модель
  ↓
реализация
  ↓
эксперимент
  ↓
метрики
  ↓
ограничения
  ↓
воспроизводимость
  ↓
следующий рубеж
```

Эталон глубины оформления: [`Shtenco/dlp_solver`](https://github.com/Shtenco/dlp_solver).

---

## 🚀 Roadmap документации и реализации

- [ ] описать реальный file tree после появления/ревизии исходников;
- [ ] добавить Mermaid-диаграмму уже фактических модулей;
- [ ] закрепить inputs/outputs в машиночитаемой схеме;
- [ ] добавить smoke/integration/negative tests;
- [ ] сохранить benchmark/evidence artifacts;
- [ ] задокументировать связи с соседними репозиториями;
- [ ] добавить CI-проверку README и битых cross-repo links;
- [ ] повысить статус только после воспроизводимой проверки.

---

## 🛑 Что этот репозиторий пока НЕ утверждает

- что концептуальная архитектура уже является production-системой;
- что наличие README доказывает работоспособность;
- что cross-repo связь означает готовую интеграцию;
- что непроверенные performance/security/economic claims являются фактами;
- что этот репозиторий может присваивать authority соседнего домена.

---

## Коротко

```text
одна ответственность
      ↓
явные границы
      ↓
проверяемые артефакты
      ↓
связь с 75-repo federation
      ↓
только затем GREEN
```
