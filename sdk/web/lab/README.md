# Laboratório do canal web (não publicado)

`sentomaru-web-signals.mjs` é o coletor da página do W-20 (`docs/web/W20_BOT_COLLECTOR_DESIGN.md`), **só para laboratório e em modo sombra**. Não faz parte do pacote `@ebees/sentomaru-web` (`files` e `exports` não o citam), não tem entrada em `SRI.json` e **não deve rodar em tráfego de visitante real** até a banca W-22 medir o falso positivo (decisão de 12/11/2026 sobre D-PR1/D-PR2: legítimo interesse, retenção igual à da avaliação do Fraud). Está desligado a menos que o chamador passe `enabled: true`; sem isso não lê nada.

```bash
node --test sentomaru-web-signals.test.mjs
```

O objeto devolvido (`sentomaru-web-signals/1`) só tem booleanos ou `null` e é lido do lado do servidor por `WebBotSignalsInput`. Os vetores compartilhados estão em `contracts/web/web-bot-signals-vectors-v1.json`. Os valores são declaração do código da página: quem controla o cliente os muda, e um valor ausente não prova nada. As listas de nomes e de pares lidas por S2, S3 e S4 são uma escolha inicial **não medida**; a bancada W-22 decide o que fica.
