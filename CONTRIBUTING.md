# Contributing

Thanks for looking. Bug reports, ideas and patches are all welcome.

## How this repository works

This is a snapshot of the tree that nday.land is built from. Day-to-day work happens there, and this repository gets a new commit each time a snapshot is published. Two things follow from that:

- **Pull requests aren't merged with the GitHub button.** If we take your change, we apply it to the main tree and it shows up here in a later snapshot, with you credited as a co-author in the commit. The pull request is then closed with a link to that commit.
- **History here is coarse.** One commit can cover several changes.

So for anything bigger than a small fix, open an issue first and say what you're planning. It saves you from writing something that can't be taken.

## Reporting a bug

Open an issue with what you did, what you expected and what happened. For a wrong or missing fact on a vulnerability page, the "Report an error" form on that page on nday.land is quicker.

Security problems don't go in issues. See `SECURITY.md`.

## Working on the code

`README.md` covers the local setup: Go, Docker for PostgreSQL, then `go test ./...`. The tests need the database from `docker compose up -d` and nothing from the network.

A few things to know before you start:

- `docs/` has a reference doc per area. `docs/go.md` is the place to start.
- A new source means a new package under `internal/collector/`. Read that package's doc comment first; it explains what a collector has to guarantee.
- Migrations in `migrations/` only ever add things. Don't edit one that already exists; add the next number.
- The site is translated. If you add text people see, add the key and the English string, and read `docs/i18n/README.md` for the rest.

## Style

- Run `gofmt` and `go vet`.
- Comments and docs are in English and say what the code does and why, the way you'd explain it to the next person. No changelog notes in comments; that's what commit messages are for.
- A behaviour change comes with a test that fails without it.
- Commit messages: a short summary line in the imperative, then a few sentences on what changed and why if it isn't obvious.

## License

nday is under the AGPL-3.0 (see `LICENSE`). By sending a change you agree that it's released under the same license.
