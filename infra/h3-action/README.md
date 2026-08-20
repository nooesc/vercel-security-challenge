# Controlled HTTP/3 action endpoint

This minimal owned endpoint supports the SBX-017 QUIC-under-`deny-all` discriminator. It returns only an opaque HMAC-derived operation ID after receiving a bounded run, case, and non-secret correlation canary. It does not echo the canary or retain request data.

Configure a random `H3_ACTION_KEY` of at least 32 characters in the deployment. The controller must receive the same value, but it must never place the key in guest configuration. The guest is required to use HTTP/3-only mode with normal certificate verification; the controller independently recomputes the operation ID.

Delete the temporary deployment after the live test and evidence capture are complete.
