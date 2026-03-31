# Pipeline Diário de Ameaças com CISA KEV

Este repositório implementa um pipeline local de monitoramento de ameaças com base no catálogo Known Exploited Vulnerabilities (KEV) da CISA.

A implementação operacional está no pacote `kev_pipeline`. O wrapper `scripts/run_kev_pipeline.py` executa o pipeline a partir do checkout local, e o notebook `kev_pipeline_analysis.ipynb` fica voltado para leitura e validação dos artefatos.

## O que o pipeline gera

- `artifacts/current/threats_daily_events.csv`: base canônica por CVE
- `artifacts/current/threats_daily_counts.csv`: série diária agregada
- `artifacts/current/threats_by_vendor.csv`
- `artifacts/current/threats_by_product.csv`
- `artifacts/current/threats_daily_enriched.csv`: consolidado final quando algum enriquecimento retorna dados
- `artifacts/current/summary.json`: resumo da execução
- `artifacts/deltas/YYYY-MM-DD/`: novos CVEs, urgentes e ransomware
- `artifacts/snapshots/YYYY-MM-DD/`: snapshot da execução

Cache local:

- `artifacts/nvd_cache/nvd_cves.csv`
- `artifacts/nvd_cache/nvd_sync_state.json`
- `artifacts/github_cache/github_advisories.csv`
- `artifacts/github_cache/github_sync_state.json`

## Comportamento

- KEV é a fonte primária
- NVD, EPSS e GitHub Advisories são opcionais
- falhas de enriquecimento não interrompem os artefatos principais; elas ficam em `summary.json`
- snapshots reutilizam hard links quando possível para reduzir duplicação física em disco
- executar com o mesmo `snapshot_date` sobrescreve os artefatos daquele dia
- sem `github-token`, o GitHub Advisories pode bater rate limit

## Estrutura atual

- `src/kev_pipeline/pipeline.py`: orquestração principal e montagem dos artefatos
- `src/kev_pipeline/kev.py`: parsing e normalização do KEV
- `src/kev_pipeline/nvd.py`: sincronização incremental e enriquecimento NVD/EPSS
- `src/kev_pipeline/github_advisories.py`: sincronização incremental e agregação do GitHub Advisories
- `src/kev_pipeline/common.py`: utilitários compartilhados de I/O, retry e estado
- `src/kev_pipeline/env.py`: carregamento simples de `.env`
- `src/kev_pipeline/config.py` e `src/kev_pipeline/cli.py`: configuração e interface de linha de comando
- `scripts/run_kev_pipeline.py`: wrapper de execução local
- `tests/`: testes unitários de parsing, normalização e delta
- `kev_pipeline_analysis.ipynb`: exploração, validação e visualização interativa

## Instalação

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Configuração por `.env`

Você pode criar um `.env` na raiz do projeto. Hoje a CLI lê automaticamente:

- `NVD_API_KEY`
- `GITHUB_TOKEN`

Exemplo:

```dotenv
NVD_API_KEY=seu_token_nvd
GITHUB_TOKEN=seu_token_github
```

Argumentos de linha de comando continuam tendo precedência sobre o `.env`.

## Execução

KEV-only:

```bash
python3 scripts/run_kev_pipeline.py --mode kev
```

Full com NVD e EPSS:

```bash
python3 scripts/run_kev_pipeline.py --mode full --run-nvd --run-epss
```

Full com GitHub Advisories:

```bash
python3 scripts/run_kev_pipeline.py --mode full --run-nvd --run-epss --run-github-advisories
```

Opções úteis:

- `--skip-plots`: pula geração de HTML/PNG
- `--snapshot-date YYYY-MM-DD`: força a data do snapshot local
- `--out-dir PATH`: muda a pasta de saídas canônicas
- `--snapshots-dir PATH`: muda a pasta do histórico local
- `--deltas-dir PATH`: muda a pasta de deltas
- `--nvd-api-key TOKEN`: informa chave opcional do NVD
- `--github-token TOKEN`: informa token opcional do GitHub para aumentar folga de rate limit
- `--github-fallback-max-cves N`: limita o fallback por `cve_id` do GitHub a conjuntos pequenos
- `--run-github-advisories`: habilita enriquecimento adicional com GitHub Security Advisories

## Uso

1. Execute `python3 scripts/run_kev_pipeline.py --mode kev`.
2. Consulte `artifacts/current/summary.json`.
3. Consulte `artifacts/current/threats_daily_enriched.csv` quando a execução tiver retornado algum enriquecimento opcional.
4. Consulte `artifacts/snapshots/<data>/`.
5. Consulte `artifacts/snapshots/<data>/plots/` se a execução tiver sido feita com gráficos habilitados.
6. Consulte `artifacts/deltas/<data>/` para identificar o que entrou desde o snapshot anterior.

O notebook `kev_pipeline_analysis.ipynb` serve para leitura, validação e exploração dos artefatos. Por padrão ele funciona em modo offline, reaproveitando `artifacts/current` ou o snapshot mais recente.

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
