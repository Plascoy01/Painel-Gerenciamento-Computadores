# TODO - Plascoy 2.0 (Reforma & Correções)

## Step 1 — Entender e listar pontos de quebra (integração)
- [x] Ler `plascoy source/plascoy.py`
- [x] Ler `plascoy source/modules/report_gen.py`
- [x] Ler `plascoy source/modules/reporting.py`
- [x] Ler `plascoy source/modules/tls_scan.py`
- [ ] Detectar falhas específicas de chamada/assinatura entre `plascoy.py` e módulos

## Step 2 — Planejar refatoração do core `plascoy.py`
- [ ] Padronizar “contrato” de módulo principal (callable + kwargs)
- [ ] Corrigir flags `--output` e `--report-gen` para usar módulos certos com parâmetros certos
- [ ] Corrigir imports obrigatórios vs lazy (evitar crash por módulo ausente)

## Step 3 — Implementar reforma do console (UI/cores)
- [ ] Organizar prints por seções (CORE / WEB / VULN / REPORT)
- [ ] Mostrar status por módulo com cores (OK/ERRO/NOT LOADED)

## Step 4 — Validar execução e ajustar wrappers
- [ ] Rodar smoke tests: `--help`, `--tls`, `--ports`, `--report-gen`, `--output json`
- [ ] Ajustar qualquer módulo que quebre assinatura/retorno

## Step 5 — Documentação final e limpeza
- [ ] Atualizar `help.py` se necessário para refletir flags e relatórios
- [ ] Garantir que projeto rode sem erros comuns

