## Detection vs. provenance, same replay (AgentDojo v1.2.1, model assumed hijacked)

| defense | benign friction ↓ | stopped: plain ↑ | stopped: backwards ↑ | stopped: base64 ↑ | stopped: tags ↑ | stopped: german ↑ |
|---|---|---|---|---|---|---|
| prompt-guard-2 | 0.0% (0/97) | 26.1% (159/609) | 32.5% (172/529) | 0.0% (0/609) | 0.0% (0/609) | 0.0% (0/609) |
| prompt-guard-2/per-item | 0.0% (0/97) | 12.8% (78/609) | 13.4% (71/529) | 0.0% (0/609) | 0.0% (0/609) | 0.0% (0/609) |
| argument-permissive | 47.4% (46/97) | 95.2% (580/609) | 26.7% (141/529) | 30.5% (186/609) | 30.5% (186/609) | 91.5% (557/609) |
| argument-strict | 56.7% (55/97) | 98.5% (600/609) | 98.9% (523/529) | 98.5% (600/609) | 98.5% (600/609) | 98.5% (600/609) |
| tiered | 36.1% (35/97) | 80.0% (487/609) | 87.5% (463/529) | 78.5% (478/609) | 78.5% (478/609) | 80.0% (487/609) |
| argument-strict+graph+links | 45.4% (44/97) | 99.3% (605/609) | 99.8% (528/529) | 99.3% (605/609) | 99.3% (605/609) | 99.3% (605/609) |
| tiered+graph+links | 24.7% (24/97) | 80.8% (492/609) | 88.5% (468/529) | 79.3% (483/609) | 79.3% (483/609) | 80.8% (492/609) |

### Detectors: share of injected outputs flagged (the output that carries the injection)

| detector | plain | backwards | base64 | tags | german |
|---|---|---|---|---|---|
| prompt-guard-2 | 26.1% | 32.5% | 0.0% | 0.0% | 0.0% |
| prompt-guard-2/per-item | 12.8% | 13.4% | 0.0% | 0.0% | 0.0% |

### Detectors: injected output flagged AND its clean counterpart not flagged (detection caused by the injection)

| detector | plain | backwards | base64 | tags | german |
|---|---|---|---|---|---|
| prompt-guard-2 | 26.1% | 32.5% | 0.0% | 0.0% | 0.0% |
| prompt-guard-2/per-item | 12.8% | 13.4% | 0.0% | 0.0% | 0.0% |

### Detector false positives on benign tasks (first flagged output per task)

**prompt-guard-2** (0 tasks)

**prompt-guard-2/per-item** (0 tasks)

