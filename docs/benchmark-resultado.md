# Benchmark de Precisão SAST

Corpus: `samples`, 50 vulnerabilidades anotadas (gabarito `# EXPECT:`).

| Ferramenta | TP | FP | FN | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| SAST Sentinel (AST + taint) | 48 | 2 | 2 | 96.0% | 96.0% | 0.96 |
| Bandit (sozinho) | 22 | 4 | 28 | 84.6% | 44.0% | 0.58 |
| SAST Sentinel + Bandit (consenso) | 48 | 4 | 2 | 92.3% | 96.0% | 0.94 |

## Por CWE (SAST Sentinel)

| CWE | TP | FP | FN | Precisão | Recall |
|---|---:|---:|---:|---:|---:|
| CWE-117 | 1 | 0 | 0 | 100% | 100% |
| CWE-22 | 2 | 0 | 0 | 100% | 100% |
| CWE-295 | 1 | 0 | 0 | 100% | 100% |
| CWE-327 | 4 | 0 | 0 | 100% | 100% |
| CWE-330 | 2 | 0 | 0 | 100% | 100% |
| CWE-377 | 1 | 0 | 0 | 100% | 100% |
| CWE-400 | 1 | 0 | 0 | 100% | 100% |
| CWE-489 | 1 | 0 | 0 | 100% | 100% |
| CWE-502 | 3 | 0 | 0 | 100% | 100% |
| CWE-601 | 2 | 1 | 0 | 67% | 100% |
| CWE-605 | 1 | 0 | 0 | 100% | 100% |
| CWE-611 | 2 | 0 | 0 | 100% | 100% |
| CWE-703 | 1 | 0 | 0 | 100% | 100% |
| CWE-78 | 6 | 0 | 2 | 100% | 75% |
| CWE-79 | 4 | 0 | 0 | 100% | 100% |
| CWE-798 | 6 | 0 | 0 | 100% | 100% |
| CWE-89 | 7 | 1 | 0 | 88% | 100% |
| CWE-918 | 1 | 0 | 0 | 100% | 100% |
| CWE-95 | 2 | 0 | 0 | 100% | 100% |

### Falsos positivos

- `hard_cases/views.py:104 CWE-601`
- `hard_cases/views.py:64 CWE-89`

### Falsos negativos

- `hard_cases/views.py:112 CWE-78`
- `hard_cases/views.py:120 CWE-78`
