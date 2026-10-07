# Política de Dados Públicos

Este repositório público adota uma política que prioriza dados sintéticos.

Credenciais reais, tokens, chaves privadas, dados pessoais, documentos
confidenciais, evidências de clientes, identificadores internos e logs
sensíveis de produção não devem ser commitados.

Materiais de demonstração e teste devem ser sintéticos por construção
ou explicitamente públicos.

Faixas e domínios reservados para documentação devem ser priorizados
nos exemplos, incluindo endereços TEST-NET e domínios de exemplo.

Se a condição de publicação de qualquer artefato for incerta, trate-o
como sensível e não faça commit.

A revisão de segurança utiliza defesa em profundidade. Um scan de
segredos limpo, isoladamente, não constitui autorização para publicar
dados.

A publicação no repositório exige, quando aplicável:

- revisão dos dados sintéticos ou públicos;
- scan automatizado de segredos;
- testes contra vazamento acidental;
- inspeção do diff staged;
- revisão de segurança e Red Team;
- quality gates globais limpos.

Evidências originais provenientes de investigações reais nunca devem
ser copiadas para este repositório público.
