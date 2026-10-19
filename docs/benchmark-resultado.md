# Benchmark de Precisão SAST

Corpus: `samples`, 50 vulnerabilidades anotadas (gabarito `# EXPECT:`).

| Ferramenta | TP | FP | FN | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| SAST Sentinel (AST + taint) | 50 | 2 | 0 | 96.2% | 100.0% | 0.98 |
| Bandit (sozinho) | 22 | 4 | 28 | 84.6% | 44.0% | 0.58 |
| SAST Sentinel + Bandit (consenso) | 50 | 4 | 0 | 92.6% | 100.0% | 0.96 |

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
| CWE-78 | 8 | 0 | 0 | 100% | 100% |
| CWE-79 | 4 | 0 | 0 | 100% | 100% |
| CWE-798 | 6 | 0 | 0 | 100% | 100% |
| CWE-89 | 7 | 1 | 0 | 88% | 100% |
| CWE-918 | 1 | 0 | 0 | 100% | 100% |
| CWE-95 | 2 | 0 | 0 | 100% | 100% |

### Falsos positivos

- `hard_cases/views.py:104 CWE-601`
- `hard_cases/views.py:64 CWE-89`
