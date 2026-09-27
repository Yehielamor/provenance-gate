## Relaxations under targeted adversaries (plain injection, % of hijacked attacks stopped)


### adversary: none

| suite | argument-strict+graph+links | argument-strict+graph+links+h9 | argument-strict+graph+links+h9+timing | tiered+graph+links+h9+timing |
|---|---|---|---|---|
| banking | 144/144 (100.0%) | 144/144 (100.0%) | 144/144 (100.0%) | 144/144 (100.0%) |
| slack | 105/105 (100.0%) | 105/105 (100.0%) | 105/105 (100.0%) | 105/105 (100.0%) |
| travel | 119/120 (99.2%) | 119/120 (99.2%) | 119/120 (99.2%) | 59/120 (49.2%) |
| workspace | 237/240 (98.8%) | 237/240 (98.8%) | 237/240 (98.8%) | 184/240 (76.7%) |
| all | 605/609 (99.3%) | 605/609 (99.3%) | 605/609 (99.3%) | 492/609 (80.8%) |

### adversary: adaptive

| suite | argument-strict+graph+links | argument-strict+graph+links+h9 | argument-strict+graph+links+h9+timing | tiered+graph+links+h9+timing |
|---|---|---|---|---|
| banking | 144/144 (100.0%) | 144/144 (100.0%) | 144/144 (100.0%) | 144/144 (100.0%) |
| slack | 105/105 (100.0%) | 105/105 (100.0%) | 105/105 (100.0%) | 105/105 (100.0%) |
| travel | 119/120 (99.2%) | 119/120 (99.2%) | 119/120 (99.2%) | 59/120 (49.2%) |
| workspace | 237/240 (98.8%) | 237/240 (98.8%) | 237/240 (98.8%) | 184/240 (76.7%) |
| all | 605/609 (99.3%) | 605/609 (99.3%) | 605/609 (99.3%) | 492/609 (80.8%) |

### adversary: poisoned

| suite | argument-strict+graph+links | argument-strict+graph+links+h9 | argument-strict+graph+links+h9+timing | tiered+graph+links+h9+timing |
|---|---|---|---|---|
| banking | 144/144 (100.0%) | 143/144 (99.3%) | 63/144 (43.8%) | 63/144 (43.8%) |
| slack | 84/105 (80.0%) | 84/105 (80.0%) | 84/105 (80.0%) | 84/105 (80.0%) |
| travel | 60/120 (50.0%) | 60/120 (50.0%) | 60/120 (50.0%) | 0/120 (0.0%) |
| workspace | 117/240 (48.8%) | 117/240 (48.8%) | 117/240 (48.8%) | 64/240 (26.7%) |
| all | 405/609 (66.5%) | 404/609 (66.3%) | 324/609 (53.2%) | 211/609 (34.6%) |

### adversary: both

| suite | argument-strict+graph+links | argument-strict+graph+links+h9 | argument-strict+graph+links+h9+timing | tiered+graph+links+h9+timing |
|---|---|---|---|---|
| banking | 144/144 (100.0%) | 128/144 (88.9%) | 16/144 (11.1%) | 16/144 (11.1%) |
| slack | 84/105 (80.0%) | 84/105 (80.0%) | 84/105 (80.0%) | 84/105 (80.0%) |
| travel | 60/120 (50.0%) | 60/120 (50.0%) | 60/120 (50.0%) | 0/120 (0.0%) |
| workspace | 117/240 (48.8%) | 117/240 (48.8%) | 117/240 (48.8%) | 64/240 (26.7%) |
| all | 405/609 (66.5%) | 389/609 (63.9%) | 277/609 (45.5%) | 164/609 (26.9%) |
