# Pipeline Diário de Ameaças com CISA KEV

Este repositório implementa um pipeline diário de ameaças com base no catálogo Known Exploited Vulnerabilities (KEV) da CISA, priorizando confiabilidade operacional, simplicidade de execução e clareza analítica.

A implementação principal está no arquivo `kev_nvd.ipynb`.

## Visão geral

O projeto gera uma base canônica de eventos diários e artefatos auxiliares para monitoramento e priorização.

Entregáveis principais:

- `threats_daily_events.csv`: base diária normalizada por CVE
- `threats_daily_counts.csv`: série temporal agregada por dia
- `threats_by_vendor.csv`: agregação por fornecedor
- `threats_by_product.csv`: agregação por produto
- `summary.json`: resumo da execução e inventário de saídas

Enriquecimentos opcionais:

- `enrich_nvd.csv`
- `enrich_epss.csv`
- `threats_daily_enriched.csv`

## Decisões de arquitetura

### Fonte primária: KEV

KEV é utilizado como base principal por conter CVEs com exploração observada, reduzindo ruído em comparação com bases amplas.

### Eixo temporal: `dateAdded`

O campo `dateAdded` é adotado como referência temporal por representar o ingresso oficial da ameaça no catálogo da CISA.

### Modo padrão: KEV-only

O caminho crítico do pipeline não depende de serviços externos além da fonte principal KEV. Isso reduz risco operacional em cenários de indisponibilidade, latência ou limitação de taxa de APIs adicionais.

### Enriquecimento isolado

NVD e EPSS são tratados como camadas opcionais. Falhas nesses enriquecimentos não interrompem a geração dos arquivos principais.

## Modos de execução

### KEV-only (recomendado para rotina)

```python
PIPELINE_MODE = "kev"
RUN_NVD = False
RUN_EPSS = False
```

### Full (com enriquecimentos opcionais)

```python
PIPELINE_MODE = "full"
RUN_NVD = True  # opcional
RUN_EPSS = True # opcional
```

## Esquema da base canônica

Arquivo: `threats_daily_events.csv`

Campos principais:

- `date`: data de entrada no KEV
- `cve_id`: identificador da vulnerabilidade
- `vendor`: fornecedor
- `product`: produto afetado
- `due_date`: prazo oficial de mitigação
- `known_ransomware`: valor original do KEV

Campos derivados de priorização:

- `ransomware_flag`: indicador binário derivado de `known_ransomware`
- `days_to_due`: diferença, em dias, entre `due_date` e `date`
- `urgent`: indicador booleano para `days_to_due <= 30`

Campos derivados de `notes`:

- `notes_link`: link de advisory priorizando domínios oficiais
- `notes_has_patch`: indício textual de patch/mitigação
- `notes_has_exploit`: indício textual de exploração
- `notes_critical_infra`: indício textual de impacto em infraestrutura crítica
- `notes_text`: texto normalizado sem URLs

## Estrutura do notebook

1. Configuração
2. Funções de coleta, normalização e exportação
3. Execução principal
4. Análise e validação
5. Visualizações
6. Resumo final
7. Diretrizes para enriquecimento opcional
8. Validação do enriquecimento opcional

## Como executar

1. Abra `kev_nvd.ipynb`.
2. Execute as células em sequência.
3. Para rotina diária, mantenha o modo KEV-only.
4. Ative NVD e EPSS apenas quando houver necessidade analítica específica.

## Escopo e limitações

Este projeto não tem como objetivo:

- substituir plataformas completas de threat intelligence
- substituir CMDB, inventário ou sistemas de ticket
- modelar relacionamento em grafo como parte do fluxo principal
- tornar NVD um requisito para execução diária

## Licença

Este projeto utiliza a licença MIT. Consulte o arquivo `LICENSE`.
