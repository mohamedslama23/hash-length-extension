# Hash Length Extension Attack

A linear game for the [CyberRangeCZ Platform](https://docs.platform.cyberrange.cz/), adapted from the
SEED *Hash Length Extension Attack Lab* by Wenliang Du.

Each student gets one sandbox with **unique flags and MAC keys** (APG variant answers), so flags cannot be shared.

## Game levels summary
| # | Level | Points | Skill |
|-|-|-|-|
| 1 | Send a valid request | 4 | compute `SHA256(key:msg)` MAC |
| 2 | Build the padding | 4 | construct SHA-256 padding |
| 3 | Length extension attack | 8 | forge a MAC without the key |
| 4 | Fix it with HMAC | 4 | use HMAC, explain the fix |
| | **Total** | **20** | |

Hint penalties range from **-0.5 to -2** points.

## Topology summary
| Host | Image | Flavor | Network | Role |
|-|-|-|-|-|
| attacker | SEED (seed-ubuntu-20.04) | m1.medium | attacker-switch (10.1.27.23) | student workstation |
| server | SEED (seed-ubuntu-20.04) | m1.medium | server-switch (10.1.26.80) | hidden MAC web server (Docker) |
| router | debian-12-x86_64 | m1.medium | both | routing |

The `server` runs the **SEED Labsetup Docker container** (`provisioning/roles/server/files/Labsetup`) built and
started by Ansible; the web server is published on the host's port 80. The server network is
`accessible_by_user: False` and SSH password login is disabled, so students reach the app only over HTTP as
`www.seedlab-hashlen.com` and cannot `docker exec` in to read flags. The student's own uid is not allowed to
download `secret.txt`, so the Task 3 flag is reachable only by performing the attack.

> **Before import, set `image:` and `mgmt_user:` in `topology.yml`** (same SEED image on both `attacker` and
> `server`) to match the exact name of your SEED Glance image and its management user. Everything else is ready.

## How per-student flags work
`variables.yml` generates random `flag_task1..4` and two uids per sandbox. The Ansible provisioning derives the
MAC keys from those flags and writes the flag files and `key.txt`. In `training.json` each task uses
**Variant Answers** with the matching variable name, so the platform grades every student against their own flag.

## License
Code (Ansible, Flask app) under MIT. Game design under CC BY 4.0. See `ATTRIBUTION.txt`.
