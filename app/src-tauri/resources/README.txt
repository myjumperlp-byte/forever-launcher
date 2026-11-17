For a local build: put your server CA certificate here as forever_root_ca.crt (from certs/ca/ after
scripts/gen-certs.sh), or set the FOREVER_CA_CERT variable to its text. It is public; never copy the .key.
GitHub Actions uses the FOREVER_CA_CERT repository variable instead (see the README).

This copy is only the fallback: on every start the launcher also asks <website>/forever_root_ca.crt for the
CA the server uses right now (static/ca.rs) and, when it differs from the one trusted on this PC, installs
it. Re-running scripts/gen-certs.sh on the server therefore no longer breaks the game connection, even for
launchers built before the change.
