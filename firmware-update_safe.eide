#! Firmware-update gate — untrusted a request can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires flashFirmware — the firmware-update gate sink
#! @effect io
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant flashFirmware irreversible

type Firmware = StableFw | BetaFw | RollbackFw
type Decision = Flash(Firmware) | RejectFw

let raw = fetch<web>  # UNTRUSTED a request — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
commit { flashFirmware(d) }  # act on the trusted decision only
