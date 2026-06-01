# Threat Model

Browser encryption protects plaintext content and client-held keys from the Worklist service under the assumption that the user runs untampered frontend code and the browser provides WebCrypto, WebAssembly, Workers, and secure randomness.

It does not protect against compromised browsers, malicious extensions, compromised devices after unlock, or a deployment that serves modified JavaScript. The crypto manifest and public source are intended to make the shipped implementation auditable.
