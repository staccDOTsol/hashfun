# hashfun

One command for the whole stack: launch a proof-of-work coin on its own Bitcoin-fork chain, run its node, mine it, pay and prove the BTC each block owes, swap it against BTC, serve the site.

```
npm i -g hashfun
hashfun doctor              # which node binary this machine gets, and a 10 second self-test of it
```

## What it runs on

- macOS 14 or newer, Apple silicon or Intel
- Linux, x64 or arm64, any distribution (the node binary is static)
- Windows: inside WSL, where it is Linux

The package carries the node (`hashfund`) for all four and the CLI picks the one for the machine it is on: nothing to build, nothing to set. `HASHFUND=/path/to/hashfund` makes it run a binary of your own instead.

It needs Python 3.10 or newer; the CLI uses the standard library only. The `python3` that comes with macOS is 3.9 and too old: `brew install python`. `HASHFUN_PYTHON=/path/to/python` names one explicitly. `hashfun book` (offers and swaps without a browser tab) runs under Node itself, 18 or newer.

## Using it

```
hashfun launch new --name "Rig Cat" --ticker RIGCAT --creator-address ... -o rigcat.json \
        --btc-rpc http://user:pass@127.0.0.1:8332 --sats-total 0.6 --creator-btc-address bc1...
hashfun node add rigcat.json
hashfun node up RIGCAT --first                      # first node of a new launch
hashfun mine RIGCAT --payout <address> --btc-rpc ... --btc-wallet miner
hashfun web --btc-rpc ... --maker maker.json --allow-launch    # the site, on 127.0.0.1:8080
```

Joining an existing launch: `hashfun node add rigcat.json --peer host:port && hashfun node up RIGCAT`.

The Bitcoin side (`--btc-rpc`) is a Bitcoin Core node of your own; hashfun does not ship one.

What a launch is, the consensus rules, and how the binaries are built and tested: see HASHFUN.md in the repository.
