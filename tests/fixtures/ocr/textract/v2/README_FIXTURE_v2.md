# KUMA Textract Fixture v2

Fixture sintética e determinística criada para o Challenge 01 do KUMA Secure Knowledge Pipeline.

## Objetivo
Fornecer um artefato PNG válido, público e reproduzível para testes de OCR com Amazon Textract.

## Arquivos
- `KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png`: artefato de entrada.
- `KUMA_TEXTRACT_FIXTURE_INCIDENT_v2_expected.txt`: baseline textual esperado.
- `KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.sha256.txt`: SHA-256 do artefato.
- `KUMA_TEXTRACT_FIXTURE_INCIDENT_v2_manifest.json`: metadados e proveniência.

## Política
- 100% sintética.
- Sem dados reais de clientes.
- Sem segredos.
- Usa `198.51.100.24` (TEST-NET-2) para documentação.
- Usa `vpn.corp.example.com` como domínio de exemplo.
- Não alterar silenciosamente após a primeira execução real. Mudanças exigem nova versão.

## Referências verificáveis
O texto esperado, o manifesto e o SHA-256 permitem conferir
a referência pública e a integridade da imagem sintética.

## Uso
Esta fixture destina-se a demonstrações e testes de OCR
sem dados reais de clientes ou incidentes.
