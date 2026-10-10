# KUMA Secure Knowledge Pipeline

![KUMA Secure Knowledge Pipeline](docs/assets/branding/KUMA_HEADER_README_v3.png)

[![Security CI](https://github.com/KUMA-LAB-1/kuma-secure-knowledge-pipeline/actions/workflows/security-ci.yml/badge.svg)](https://github.com/KUMA-LAB-1/kuma-secure-knowledge-pipeline/actions/workflows/security-ci.yml)

**Pipeline de segurança orientado por evidências, com extração OCR, validação de integridade, orquestração e enriquecimento por IA generativa.**

O projeto transforma documentos sintéticos de segurança em evidências rastreáveis e resultados estruturados para apoiar a análise humana. A arquitetura separa contratos de domínio, adaptadores de fornecedores e mecanismos de persistência, priorizando testes reproduzíveis e falhas controladas.

## Visão geral

```text
Documento de demonstração
          |
          v
OCR (Tesseract local ou adapter Textract testado com respostas sintéticas)
          |
          v
Evidence Bundle: raw-response.json | normalized.json | extracted.txt | manifest.json
          |
          v
LoadEvidence -> BuildRequest -> Enrich -> PersistResult
          |                           |
          |                           +-> GenAIProvider (Ollama local / fake para testes)
          v
Resultado estruturado, referenciado e persistido localmente
```

O bundle preserva a resposta original do extrator, os dados normalizados, o texto reconhecido e o manifesto de proveniência. Referências de evidência e verificações SHA-256 permitem identificar inconsistências antes do enriquecimento.

## Funcionalidades implementadas

| Componente | Implementação |
|---|---|
| **OCR e evidências** | Extração real com Tesseract local, adapter Textract exercitado com respostas sintéticas, normalização, proveniência e publicação de bundles |
| **Contratos GenAI** | Requisições limitadas por tamanho, validação de JSON e saídas estruturadas vinculadas a identificadores autorizados de evidência |
| **Inferência local** | Adapter Ollama para modelos aprovados; inferência real com Qwen demonstrada separadamente dos testes automatizados |
| **Orquestração offline** | Handlers `LoadEvidence`, `BuildRequest`, `Enrich`, `PersistResult` e `AuditFailure` |
| **Persistência local** | Registros endereçados por conteúdo, escopo por execução e publicação idempotente |
| **AWS Step Functions** | Definição ASL de referência, com testes estruturais locais, sem implantação na AWS |

O resultado GenAI separa **fatos com referências**, **hipóteses**, **evidências ausentes** e **verificações recomendadas**. O contrato impede que o modelo marque um incidente como confirmado automaticamente. Uma referência válida demonstra vínculo estrutural, **não comprova por si só a veracidade da afirmação**.

### Evidência de demonstração

A amostra abaixo é **sintética** e foi preparada para testes reproduzíveis, sem dados de clientes ou incidentes reais.

![Documento sintético utilizado nos testes OCR](tests/fixtures/ocr/textract/v2/KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png)

Em uma execução real do Tesseract local, o identificador MITRE ATT&CK `T1110` foi reconhecido como `71110`. O projeto preservou a leitura original, demonstrando por que resultados OCR precisam de conferência antes de sustentar decisões de segurança.

## Executando localmente

**Requisitos:** Python 3.12+, [uv](https://docs.astral.sh/uv/), Tesseract OCR 5.x e dados de idioma `por` para a demonstração OCR. Ollama é opcional e necessário apenas para inferência local real.

Instale as dependências Python e execute os testes:

```powershell
uv sync --locked --group dev
uv run pytest -q
uv run pytest -m smoke -q
```

Para executar a extração OCR local, ajuste os caminhos do Tesseract e do diretório de evidências ao seu ambiente Windows:

```powershell
$env:KUMA_TESSERACT_BIN = 'C:\Program Files\Tesseract-OCR\tesseract.exe'
$env:KUMA_TESSDATA_DIR = Join-Path $env:USERPROFILE 'KUMA_OCR_MODELS\tessdata'
$env:KUMA_EVIDENCE_DIR = Join-Path $env:TEMP 'kuma-ocr-demo'

@'
import os
from pathlib import Path
from kuma_secure_knowledge_pipeline.extraction.tesseract_local import run_local_tesseract_pipeline

bundle = run_local_tesseract_pipeline(
    source_path=Path('tests/fixtures/ocr/textract/v2/KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png'),
    output_root=Path(os.environ['KUMA_EVIDENCE_DIR']),
    binary_path=Path(os.environ['KUMA_TESSERACT_BIN']),
    tessdata_dir=Path(os.environ['KUMA_TESSDATA_DIR']),
    language='por',
    psm=6,
    timeout_seconds=45,
)
print('Bundle:', bundle)
'@ | uv run --locked python -
```

Use um diretório de saída fora do repositório. Cada execução cria um identificador próprio; não reutilize identificadores após falhas ambíguas nem remova reservas de execução para forçar novas tentativas.

## Qualidade e segurança

A validação da `main` após a integração da Challenge 02 registrou **296 testes aprovados**, incluindo **2 smokes funcionais**. O [Security CI pós-merge](https://github.com/KUMA-LAB-1/kuma-secure-knowledge-pipeline/actions/runs/38091003982) também aprovou Ruff, Bandit, auditoria das dependências auditáveis, detecção de segredos e higiene de diff.

Entre os controles exercitados estão validação estrita de entrada e saída, limites de recursos, rejeição de referências não autorizadas, integridade dos registros, idempotência e tratamento controlado de falhas. Os testes utilizam dados sintéticos e não garantem ausência absoluta de vulnerabilidades.

A [Política de Dados Públicos](docs/security/PUBLIC_DATA_POLICY.md) proíbe credenciais e evidências reais de clientes neste repositório.

## Limites da demonstração

- **Tesseract:** extração OCR real demonstrada em ambiente local.
- **Amazon Textract:** adapter implementado e testado com respostas sintéticas; a tentativa real não produziu OCR utilizável.
- **Ollama/Qwen:** inferência real demonstrada localmente, separada dos smokes automatizados que usam providers de teste.
- **Amazon Bedrock, AWS Step Functions, Lambda e S3:** nenhuma execução ou implantação real demonstrada neste marco. A [definição ASL](infra/stepfunctions/kuma_pipeline.asl.json) é um artefato de arquitetura, não uma state machine em produção.

A persistência local não oferece, por si só, as garantias de um serviço distribuído. O uso futuro em cloud exige adaptações e revisão específica de identidade, acesso, armazenamento, logs e tratamento de erros.

## Evolução do projeto

| Marco | Situação |
|---|---|
| **Challenge 01: OCR e evidências** | Concluído e integrado via [PR #2](https://github.com/KUMA-LAB-1/kuma-secure-knowledge-pipeline/pull/2), com tag [`v0.1.0-ocr-evidence`](https://github.com/KUMA-LAB-1/kuma-secure-knowledge-pipeline/tree/v0.1.0-ocr-evidence) |
| **Challenge 02: orquestração e GenAI** | **Concluído e integrado à `main`** via [PR #3](https://github.com/KUMA-LAB-1/kuma-secure-knowledge-pipeline/pull/3); implementação offline validada |
| **Challenge 03: knowledge pipeline e wiki** | Planejado: ingestão multiformato, indexação, recuperação, RAG e citações verificáveis |

O Release completo do projeto será considerado após a conclusão dos três marcos.

---

*Projeto independente de engenharia e segurança, desenvolvido com dados sintéticos e foco em resultados verificáveis.*
