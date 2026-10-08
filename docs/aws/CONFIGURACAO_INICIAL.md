# Configuração Segura da AWS para Desenvolvimento Local

> Guia operacional reutilizável e orientado por segurança utilizado no **KUMA Secure Knowledge Pipeline**.
>
> Este guia evita credenciais permanentes da AWS e separa claramente autenticação de permissões de serviço.

## Objetivo

Este documento descreve uma configuração inicial segura para desenvolvimento local na AWS com:

- identidade de desenvolvimento não-root;
- MFA;
- grupo IAM dedicado;
- credenciais temporárias obtidas por `aws login`;
- perfil (`profile`) nomeado;
- permissões de serviço seguindo o princípio do menor privilégio;
- região AWS definida explicitamente;
- validação da identidade efetiva antes de chamadas reais aos serviços;
- documentação pública sem IDs reais da conta ou segredos.

A configuração foi validada durante o Challenge 01 do KUMA Secure Knowledge Pipeline.

Os nomes de usuário, grupo, perfil e política IAM apresentados neste documento são exemplos públicos e não correspondem aos identificadores reais utilizados na conta do projeto.

## Modelo de segurança

```text
ROOT
  │
  │ inicialização da conta / tarefas excepcionais
  ▼
Identidade administrativa
  │
  │ cria e mantém identidades e policies
  ▼
PROJETO_DEVELOPERS
  ├── SignInLocalDevelopmentAccess
  └── ProjetoChallenge01Textract
            │
            ▼
      PROJETO_DEV
      ├── acesso ao console
      ├── MFA
      ├── sem access key permanente
      └── sessão temporária via aws login
```

Este modelo foi mantido propositalmente pequeno para uma conta standalone de laboratório independente. Ambientes maiores ou com múltiplas contas devem avaliar IAM Identity Center e IAM Roles.

## 1. Proteger o usuário root

Após criar a conta AWS:

1. habilite MFA para o root;
2. use uma senha forte e exclusiva;
3. não crie access keys para o root;
4. não utilize root no desenvolvimento cotidiano.

O root deve ficar reservado para tarefas administrativas excepcionais.

## 2. Criar uma identidade de desenvolvimento

Crie um usuário IAM dedicado, por exemplo:

```text
PROJETO_DEV
```

Configuração recomendada:

- acesso ao AWS Management Console habilitado;
- senha forte e exclusiva;
- MFA habilitado;
- nenhuma access key permanente.

Não use `aws configure` com access key permanente como atalho para desenvolvimento local.

## 3. Criar um grupo de desenvolvimento

Crie:

```text
PROJETO_DEVELOPERS
```

Adicione o usuário de desenvolvimento ao grupo.

Prefira anexar as policies ao grupo, em vez de diretamente ao usuário. Isso facilita auditoria, manutenção e substituição futura da identidade.

## 4. Habilitar login temporário local

Anexe ao grupo a policy gerenciada pela AWS:

```text
SignInLocalDevelopmentAccess
```

Essa policy permite o fluxo OAuth2 utilizado por ferramentas locais, incluindo `aws login`.

Ela autoriza ações como:

```text
signin:AuthorizeOAuth2Access
signin:CreateOAuth2Token
```

Importante: essa policy não concede acesso ao Textract, S3, Lambda, Bedrock ou outros serviços AWS. As permissões de cada serviço devem ser concedidas separadamente.

## 5. Política IAM de menor privilégio do Challenge 01

Crie uma policy gerenciada pelo cliente (`customer-managed policy`) com o nome:

```text
ProjetoChallenge01Textract
```

Exemplo:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Challenge01TextractOnly",
      "Effect": "Allow",
      "Action": [
        "textract:DetectDocumentText",
        "textract:AnalyzeDocument"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    }
  ]
}
```

Anexe essa política IAM ao grupo de desenvolvimento.

### Por que `Resource: "*"`?

Para essas operações do Textract não existe um tipo de recurso aplicável que permita restringir a autorização a um ARN específico.

Por isso, a restrição é feita pelas ações autorizadas e pela região.

### Por que `aws:RequestedRegion`?

`aws:RequestedRegion` restringe o endpoint regional solicitado.

Neste projeto:

```text
us-east-1
```

é a região autorizada para o Challenge 01.

Essa chave de condição não deve ser interpretada como garantia universal de residência de dados para todos os serviços AWS. Ela controla a região do endpoint solicitado.

## 6. Validar a sessão DEV no console

Entre no console com a identidade de desenvolvimento e MFA.

É esperado que áreas não autorizadas retornem `AccessDenied`. Isso é uma evidência positiva de que a identidade não recebeu privilégios administrativos por acidente.

Uma prática operacional útil é:

```text
Navegador/Perfil A = ADMIN
Navegador/Perfil B = DEV
```

Mantenha essas sessões visualmente separadas.

## 7. Autenticar a AWS CLI com credenciais temporárias

O comando `aws login` requer AWS CLI 2.32.0 ou superior e fornece autenticação local temporária.

Prefira um perfil (`profile`) nomeado em vez de usar `default`.

Exemplo:

```powershell
aws login `
    --remote `
    --profile projeto-dev `
    --region us-east-1
```

O modo `--remote` é útil quando existem várias sessões abertas no navegador, porque permite escolher deliberadamente o navegador DEV para concluir a autorização.

### Código de autorização (`authorization code`)

O código de autorização (`authorization code`) exibido durante o fluxo remoto:

- não é o código MFA;
- não é a senha;
- não é access key;
- é temporário;
- não deve ser compartilhado nem registrado.

Se a AWS perguntar:

```text
Configure AWS skills and the AWS MCP server for your AI coding agent(s)? [y/n/never]
```

essa integração é opcional.

Ela não é necessária para:

- `aws login`;
- boto3;
- Textract;
- o Challenge 01.

Na configuração mínima do projeto, pode ser ignorada.

## 8. Persistir e verificar a região

O argumento `--region` pode funcionar apenas como override de um comando.

Verifique o perfil (`profile`):

```powershell
aws configure get region `
    --profile projeto-dev
```

Se o resultado estiver vazio, persista explicitamente:

```powershell
aws configure set region `
    us-east-1 `
    --profile projeto-dev
```

Confirme:

```powershell
aws configure get region `
    --profile projeto-dev
```

Resultado esperado:

```text
us-east-1
```

## 9. Verificar a identidade efetiva

Antes de chamar um serviço pago ou privilegiado:

```powershell
aws sts get-caller-identity `
    --profile projeto-dev `
    --region us-east-1 `
    --no-cli-pager
```

Valide localmente que:

- a identidade não é root;
- é a identidade DEV esperada;
- a conta é a correta.

Não publique o AWS Account ID real nem ARN completo específico da conta na documentação pública.

Use placeholders:

```text
<ACCOUNT_ID_REDACTED>
<USER_NAME>
<PROFILE_NAME>
```

## 10. Auditar credenciais permanentes

As variáveis abaixo não devem estar ativas sem justificativa explícita:

```text
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN
AWS_SECURITY_TOKEN
```

Também verifique se `~/.aws/credentials` contém access keys permanentes.

Estado desejado:

```text
Perfil nomeado:          PRESENTE
Cache temporário:         PRESENTE
Chaves de acesso estáticas:    NENHUMA
Credenciais em env vars:  NENHUMA
Principal:                NÃO-ROOT
Região:                   us-east-1
```

## 11. Proteger o cache do `aws login`

O `aws login` utiliza cache local temporário.

Esse conteúdo deve ser tratado como material sensível.

Nunca:

- faça commit;
- copie para bundles de evidência;
- envie para documentação pública;
- inclua o conteúdo em screenshots ou logs.

## 12. Encerrar a sessão

Para finalizar a sessão temporária:

```powershell
aws logout `
    --profile projeto-dev
```

Isso é especialmente importante em máquinas compartilhadas ou ambientes temporários.

## Solução de problemas

### Autorização pendente expirada

Exemplo:

```text
The pending authorization to retrieve an SSO token has expired.
The login flow to retrieve an SSO token must be restarted.
```

Correção:

```text
executar aws login novamente
```

Não crie uma access key permanente como contorno.

Na configuração original do projeto, isso ocorreu porque a criação/configuração da conta demorou além da janela da autorização pendente.

### Região não persistida

Se:

```powershell
aws configure get region --profile projeto-dev
```

não retornar valor, execute:

```powershell
aws configure set region us-east-1 --profile projeto-dev
```

Scripts de auditoria também devem tratar retorno nulo antes de chamar métodos como `.Trim()`.

### Prompt do Windows Firewall

O fluxo no mesmo dispositivo (`same-device`) do `aws login` pode utilizar callback local em `127.0.0.1`, o que pode fazer o Windows Firewall exibir um prompt para `aws.exe`.

O uso de:

```powershell
aws login --remote ...
```

evita depender desse callback local e também facilita separar sessões ADMIN e DEV.

Revise regras de firewall que possam ter sido criadas com escopo excessivamente amplo, especialmente permissões para redes públicas.

## Checklist de aceitação

Antes da primeira chamada real a um serviço AWS:

- [ ] MFA do root habilitado.
- [ ] Identidade DEV não-root criada.
- [ ] MFA do DEV habilitado.
- [ ] DEV pertence a um grupo dedicado.
- [ ] `SignInLocalDevelopmentAccess` anexada.
- [ ] Policy específica do serviço seguindo o princípio do menor privilégio anexada.
- [ ] Nenhuma access key permanente usada no desenvolvimento local.
- [ ] Profile nomeado criado.
- [ ] `aws login` concluído.
- [ ] Região verificada explicitamente.
- [ ] `sts get-caller-identity` identifica o principal DEV esperado.
- [ ] Nenhuma variável inesperada de credencial AWS.
- [ ] Documentação pública sanitizada.
- [ ] Dados de teste sintéticos.
- [ ] Custo estimado da operação entendido.

## Estado validado no Challenge 01

Antes da primeira chamada ao Textract, o projeto atingiu:

```text
Profile:                  projeto-dev
Região:                   us-east-1
Tipo do principal:        IAM_USER
Identidade DEV esperada:  VERIFICADA
Cache temporário:         PRESENTE
Chaves de acesso estáticas:    NENHUMA
Credenciais em ambiente:  NENHUMA
Textract chamado:         NÃO
```

Nenhum Account ID real ou credencial deve ser armazenado no repositório.

## Melhorias futuras

Após o MVP, avaliar:

- IAM Roles;
- IAM Identity Center quando fizer sentido;
- Permission Boundaries;
- CloudTrail;
- AWS Budgets e alertas de custo;
- políticas IAM separadas por ambiente;
- desprovisionamento automatizado;
- revisão periódica de acessos não utilizados;
- IAM Access Analyzer.

## Referências oficiais da AWS

- Login local da AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html
- `SignInLocalDevelopmentAccess`: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SignInLocalDevelopmentAccess.html
- Boas práticas do root: https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
- Boas práticas de segurança do IAM: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- Chave de condição (`condition key`) `aws:RequestedRegion`: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html

---

Este documento é um exemplo de configuração segura para laboratório e desenvolvimento local. Não deve ser tratado como arquitetura IAM universal de produção. Adapte sempre as permissões ao mínimo necessário para a carga de trabalho.
