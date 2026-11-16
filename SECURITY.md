# Security

## Reporting a vulnerability

If you've found a security problem in this code or on nday.land, please email **connect@nday.land**. Don't open a public issue or pull request for it.

It helps a lot if the report has:

- what the problem is and what someone could do with it
- the steps or a request that shows it
- the commit or the URL you tested against

This is a small project, so a reply can take a few days. You'll hear back, and you'll be told when the fix is out. If you'd like to be credited, say so and how.

## What's in scope

- The code in this repository.
- The site it runs: `www.nday.land` and `api.nday.land`.

Things that aren't useful to report: missing headers with no concrete impact, rate limits being "too generous" without a way to abuse them, and findings from automated scanners with nothing to back them up.

## Testing against the live site

Please keep it gentle:

- Only use accounts you own. Don't read or change other people's data.
- No denial of service, no load testing, no spam in the discussions.
- If you run into someone else's data by accident, stop and tell us.

The easiest way to test is on your own copy. `README.md` shows how to run everything locally.

## How fixes reach this repository

This repository is a snapshot of the tree that nday.land is built from. A security fix is deployed to the site first and shows up here with the next snapshot, so the code here can be slightly behind the site, never ahead of it.

Only the current `main` is supported. There are no release branches.
