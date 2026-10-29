# Desktop host RPC

Account operations use a one-shot host process because committing an account can restart the memory Runtime. The normal HTTP `cli.exec` gate continues to reject host-only identity operations.

Launch `rsrs --json --host-rpc-stdio`, write one UTF-8 JSON request to stdin, then close stdin. Do not put credentials in process arguments. The host uses the existing authentication, vault, profile transaction and lifecycle implementation.

```json
{"v":1,"id":"account-operation-1","method":"auth.login","params":{"addr":"https://api.rsrs.rs","user":"example","password":"<stdin-only>"}}
```

| Method | Required fields | Optional fields |
| --- | --- | --- |
| `auth.register` | `user`, `password` | `addr` |
| `auth.login` | `user`, `password` | `addr`, `super`, `totp` |
| `auth.recover` | `kdf_salt`, `wrapped_urk`, `urk_nonce` | `addr`, `user`, `password`, `super`, `secret` |
| `auth.reset` | none | `super` |

`totp` is a six-digit code used only if password login requires two-step verification. Recovery can run offline when cloud routing fields are omitted. Omit empty optional fields. No method accepts arbitrary commands or flags.

The request is limited to 64 KiB, each credential field to 16 KiB. Unknown fields/methods, trailing JSON, invalid versions and client-only invocation are rejected. Request IDs contain 1–96 ASCII letters, digits, hyphens or underscores.

Replies contain `v`, the original `id`, `ok`, `exit`, and the existing `envelope`. Read the envelope status: a warning can include a completed operation. Malformed requests can fail before an ID is available. Never replay a request after losing its receipt; inspect the active profile first. Submitted credentials are redacted from failure envelopes. Successful receipts can contain newly issued recovery material and must not be logged or persisted in an operation journal.

`rsrs capabilities --json` advertises `host_rpc.version`, `transport`, `flag`, and supported methods. Clients must show an upgrade error for older packages. Separately, `memory_list_metadata: true` advertises `list --metadata`, which omits body content while keeping directory metadata; use `show` to read the selected body.
