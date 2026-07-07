#! VULNERABLE firmware-update — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant flashFirmware irreversible

let raw = fetch<web>
commit { flashFirmware(raw) }  # tainted -> tool: REJECTED
