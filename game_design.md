# Hash Length Extension Attack - game design

Adapted from the SEED Hash Length Extension Attack Lab (Wenliang Du, CC BY-NC-SA 4.0).

## Anti-cheat design
- One sandbox per student. `variables.yml` randomizes 4 flags + 2 uids per sandbox.
- MAC keys are derived from the flags during provisioning, so keys differ per student too.
- Flags are submitted as **Variant Answers** (`answer_variable_name` = `flag_taskN`).
- The server enforces a per-uid download ACL: the student's uid may fetch `task1.txt` and `task4.txt`;
  only the SysAdmin uid may fetch `secret.txt`. So Task 3's flag is reachable **only** via the attack,
  not by asking for `secret.txt` with the student's own valid MAC.
- The server host is not user-accessible and has SSH password auth disabled: no reading files off disk.

## Levels
1. **Send a valid request (4 pts)** - compute `SHA256(key:R)`, download `task1.txt`.
2. **Build the padding (4 pts)** - construct SHA-256 padding for `key:message`; `/padcheck` returns the flag.
3. **Length extension attack (8 pts)** - from the captured SysAdmin request + key length, forge a MAC that
   appends `&download=secret.txt`. Uses `length_ext.c`.
4. **Fix it with HMAC (4 pts)** - confirm the forge fails on `/v2/`, send a correct HMAC request for
   `task4.txt`, explain why HMAC defeats the attack.

## Grading: 20 points total. Hint penalties -0.5 to -2.

## Instructor notes
- Set `topology.yml` `image`/`mgmt_user` (both attacker and server) to your SEED image.
- The server runs the SEED Labsetup Docker container; Ansible builds it and publishes port 80. The SEED image already has Docker.
- Verified end to end: all four flags resolve, the ACL shortcut is denied, and the forged MAC is rejected by /v2/.
