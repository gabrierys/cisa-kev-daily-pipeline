# Pipeline Diário de Ameaças com CISA KEV

Este repositório implementa um pipeline local de monitoramento de ameaças com base no catálogo Known Exploited Vulnerabilities (KEV) da CISA.

A implementação operacional está no pacote `kev_pipeline`. O wrapper `scripts/run_kev_pipeline.py` executa o pipeline a partir do checkout local, e o notebook `kev_pipeline_analysis.ipynb` fica voltado para validação e análise.

## Visão geral

O pipeline:

- coleta o catálogo KEV como fonte primária
- normaliza uma base canônica por CVE
- gera agregações diárias, por vendor e por product
- mantém snapshots e deltas locais por data
- adiciona NVD e EPSS apenas como enriquecimentos opcionais

Entregáveis canônicos:

- `artifacts/current/threats_daily_events.csv`: base diária normalizada por CVE
- `artifacts/current/threats_daily_counts.csv`: série temporal agregada por dia
- `artifacts/current/threats_by_vendor.csv`: agregação por fornecedor
- `artifacts/current/threats_by_product.csv`: agregação por produto
- `artifacts/current/summary.json`: resumo da execução e inventário de saídas

Enriquecimentos opcionais:

- `artifacts/current/enrich_nvd.csv`
- `artifacts/current/enrich_epss.csv`
- `artifacts/current/threats_daily_enriched.csv`

Histórico local:

- `artifacts/snapshots/YYYY-MM-DD/`: snapshot completo da execução
- `artifacts/deltas/YYYY-MM-DD/new_cves_today.csv`: CVEs novos em relação ao snapshot anterior
- `artifacts/deltas/YYYY-MM-DD/new_urgent_today.csv`: novos CVEs urgentes
- `artifacts/deltas/YYYY-MM-DD/new_ransomware_today.csv`: novos CVEs com `ransomware_flag=1`

## Decisões de arquitetura

KEV é utilizado como base principal por conter CVEs com exploração observada, reduzindo ruído em comparação com bases amplas.

O campo `dateAdded` é adotado como referência temporal por representar o ingresso oficial da ameaça no catálogo da CISA.

O caminho crítico do pipeline não depende de serviços externos além da fonte principal KEV. Isso reduz risco operacional em cenários de indisponibilidade, latência ou limitação de taxa de APIs adicionais.

NVD e EPSS são tratados como camadas opcionais. Falhas nesses enriquecimentos não interrompem a geração dos arquivos principais, mas passam a ser registradas explicitamente no `summary.json`.

Os artefatos de execução ficam isolados em `artifacts/` por padrão. Isso reduz poluição na raiz do repositório, evita confusão entre código e saídas geradas e melhora a segurança operacional do projeto.

## Estrutura atual

- `src/kev_pipeline/`: pipeline, configuração e CLI
- `scripts/run_kev_pipeline.py`: wrapper de execução local
- `tests/`: testes unitários de parsing, normalização e delta
- `kev_pipeline_analysis.ipynb`: exploração, validação e visualização interativa

## Instalação

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Opcionalmente:

```bash
pip install -e .
```

## Modos de execução

### KEV-only (recomendado para rotina)

```bash
python3 scripts/run_kev_pipeline.py --mode kev
```

### Full (com enriquecimentos opcionais)

```bash
python3 scripts/run_kev_pipeline.py --mode full --run-nvd --run-epss
```

Após `pip install -e .`:

```bash
kev-pipeline --mode kev
kev-pipeline --mode full --run-nvd --run-epss
```

## Esquema da base canônica

Arquivo: `artifacts/current/threats_daily_events.csv`

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

## Opções úteis de CLI

- `--skip-plots`: pula geração de HTML/PNG e evita criar a pasta de plots
- `--snapshot-date YYYY-MM-DD`: força a data do snapshot local
- `--out-dir PATH`: muda a pasta de saídas canônicas
- `--snapshots-dir PATH`: muda a pasta do histórico local
- `--deltas-dir PATH`: muda a pasta de deltas
- `--nvd-api-key TOKEN`: informa chave opcional do NVD

## Estrutura do notebook

1. Configuração
2. Helpers de leitura dos artefatos gerados pelo pacote
3. Execução principal via pacote `kev_pipeline`
4. Análise e validação
5. Visualizações
6. Resumo final e localização dos artefatos
7. Validação da seção opcional de enriquecimento

## Como executar

1. Execute `python3 scripts/run_kev_pipeline.py --mode kev`.
   Se o pacote estiver instalado no ambiente, o equivalente é `kev-pipeline --mode kev`.
2. Consulte `artifacts/current/summary.json`.
3. Consulte `artifacts/snapshots/<data>/`.
4. Consulte `artifacts/deltas/<data>/` para identificar o que entrou desde o snapshot anterior.

Uso exploratório:

1. Abra `kev_pipeline_analysis.ipynb`.
2. Execute as células em sequência.
3. Use o notebook para análise visual ou experimentos pontuais.

## Escopo e limitações

Este projeto não tem como objetivo:

- substituir plataformas completas de threat intelligence
- substituir CMDB, inventário ou sistemas de ticket
- modelar relacionamento em grafo como parte do fluxo principal
- tornar NVD um requisito para execução diária

## Testes

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Licença

Este projeto utiliza a licença MIT. Consulte o arquivo `LICENSE`.
