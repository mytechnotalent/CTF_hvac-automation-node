# hvac-automation-node - Design Blueprint (Act IV, IRON LUNG)

Repo: `hvac-automation-node`
Companion CTF repo: `CTF_hvac-automation-node` (artifact prefix `ACT-IV`)
Codename: IRON LUNG
Author: Kevin Thomas (kevin@mytechnotalent.com)

This is the build spine. Student-facing artifacts are `README.md`, `PARTS.md`,
`NATION-STATE-REVIEW.md`, and `paper.typ`/`paper.pdf`, exactly like Acts I-III.
The companion CTF ships `ACT-IV-I/R/S.md` plus PDFs, enforced by the
`eh-project-structure` validator.

---

## Act IV of the OPERATION COLD IRON saga

Act I was the lie. Act II was the door. Act III was the payload. Act IV is the
payload that refuses to die.

WHITEOUT neutralizes the valve implant and reflashes the controller. It comes
back. The HVAC automation node is the next infected device, and this implant
learned from Act III: it hides a copy of itself in a reserved flash sector and
re-installs on every boot. Reflashing the firmware does not remove it. This is
the persistence lesson, and the rootkit that hides its own tracks.

NorthPharma is the Ministry's front; FROSTLINE wrote the persistence.

## Safety contract (real techniques, inert payloads)

- No network, no internet, no host impact. Bare-metal RP2350, no OS.
- Effects are confined to GPIO: the baffle servo, the LEDs, the LCD.
- Synthetic data only.
- A `SANDBOX_ONLY` build guard disables the implant; tests assert the implant
  cannot act outside its reserved flash sector or its own pins.
- Every act ends in analysis and neutralization.

## Parity contract with Acts I-III

- Same repo layout, same crypto stack (Argon2id + XChaCha20-Poly1305 + BLAKE2b +
  Poly1305 + envelope), same tooling, same pin map.
- Same README top/footer standard (banner, course links, `<br>`, title, `<br>`;
  footer `<br>`, `# License`, link) and the telescreen legal disclaimer.

## Pin map (identical to Acts I-III, new roles)

| Pin | Acts I-III role | Act IV role |
| --- | --------------- | ----------- |
| DHT11 GP4 | asset / interlock / process | room climate sensor |
| LCD SDA GP2 / SCL GP3 | telemetry / log / SCADA | BMS status and setpoint readout |
| IR GP5 | door / badge / operator | local override remote |
| Servo GP14 | damper / deadbolt / valve | the HVAC baffle |
| Red GP16 | breach / DENIED / FAULT | HVAC ALARM |
| Yellow GP17 | warning / PENDING / PENDING | OVERRIDE PENDING |
| Green GP18 | nominal / GRANTED / NOMINAL | HVAC NOMINAL |
| Button GP15 | acknowledge / REX / ESTOP | manual override |
| RYLR998 GP8/9 | uplink / auth / SCADA | BMS gateway link |
| Debug Probe | analysis | rootkit analysis (reserved sector) |
| Onboard GP25 | heartbeat | heartbeat |

## Fix track (vulnerabilities)

- The SETPOINT command path must be sealed and authorized (the SETPOINT
  injection).
- The local override must not bypass authorization silently.
- The node must fail to a safe setpoint on a lost link.

## Malware track (persistence + rootkit, benign)

Module `include/implant.h` + `src/implant.c`, compiled only under `SANDBOX_ONLY`:

- **Reserved-sector payload.** On first run the implant writes a payload marker
  into a reserved flash sector (`0x103FF000`).
- **Re-install on boot.** `implant_init` checks the reserved sector; if the
  marker is present it re-installs the beacon and the bomb, so a firmware
  reflash alone does not remove it.
- **Rootkit hiding.** The implant masks its own beacon from the LCD and the log,
  so the operator sees a clean node while the beacon still transmits.
- **Neutralization.** The student must erase the reserved sector and patch the
  re-install check; a firmware reflash alone is not enough.

## Companion CTF: ACT-IV, four deep tasks

| Task | Points | Objective | Skill |
| ---- | ------ | --------- | ----- |
| 1 | 10 | Setup and analysis | vector table, `main`, module map |
| 2 | 20 | Break the persistence (re-install check) | reserved-sector marker, boot path |
| 3 | 20 | Expose the rootkit hiding | LCD/log masking branch |
| 4 | 20 | Erase the reserved-sector payload | flash-sector discipline |
| 5 | 20 | Seal the SETPOINT command path | fix track |
| 6 | 10 | Export, verify, hardware proof, reflection | `ACT-IV_fixed.bin`/`.uf2`, verifier |

Every patch is in-place and same-size, so the shipped artifact can be patched
without moving any address.

## Naming

Project repo `hvac-automation-node`; companion `CTF_hvac-automation-node`; CTF
artifact prefix `ACT-IV`.
