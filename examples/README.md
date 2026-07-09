# pg examples

Runnable pure-Ruby usage of the `pg` PostgreSQL driver, verified under the [rbgo](https://github.com/go-embedded-ruby) interpreter.

```sh
rbgo examples/pg_usage.rb
```

| File | Shows |
| --- | --- |
| `pg_usage.rb` | Open a session with `PG.connect` over an injected IO seam, run a query with `#exec`, read a `PG::Result` via `#ntuples` / `#fields` / `#getvalue` / `#getisnull` / `#each`, and quote input with `#escape_string` / `#quote_ident`. |
