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

## Estratégia de validação
Comparar OCR observado contra o baseline esperado, registrando:
- cobertura de campos;
- valores críticos;
- ordem geral;
- pontuação relevante;
- confidence;
- diferenças de whitespace;
- referências de evidência;
- raw response preservado.

## Uso planejado
1. DetectDocumentText como baseline.
2. AnalyzeDocument somente após adapter, custo e gate explícitos.
3. Comparação A/B usando a mesma fixture.
