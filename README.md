# sing-quic

Протокол hysteria2.

Форк [metacubex/sing-quic](https://github.com/metacubex/sing-quic) для [miray](https://github.com/rityak/miray). Наш код — в ветке `miray`.

## Что изменено

- Клиент hysteria2 обрабатывает принятые датаграммы по порядку. Раньше на каждую запускалась горутина, и датаграммы одного потока приходили переставленными.
