# hashfun

Memecoins that are each their own Bitcoin fork: mined, priced in BTC and in QWEN, paying their holders. Every coin puts a node and a local model on more machines.

One command for the whole stack: launch a coin on its own chain, run its node, mine it on its BTC curve or its QWEN curve, pay and prove what each block owes (80% of it to a holder of the coin), swap it peer to peer, serve the site. The public site is https://aichat.fyi/fun.

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
hashfun qwork fetch                                 # Qwencoin's work table (528 MB, once): every node of a launch needs it
hashfun launch new --name "Rig Cat" --ticker RIGCAT --creator-address ... -o rigcat.json \
        --btc-rpc http://user:pass@127.0.0.1:8332 --sats-total 0.6 --creator-btc-address bc1... \
        --qwen-rpc http://user:pass@127.0.0.1:8732 --qwen-total 300 --creator-qwen-address bc1...
hashfun node add rigcat.json
hashfun node up RIGCAT --first                      # first node of a new launch
hashfun mine RIGCAT --payout <address> --curve btc --btc-rpc ... --btc-wallet miner
hashfun mine RIGCAT --payout <address> --curve qwen --qwen-rpc ... --qwen-wallet miner
hashfun web --btc-rpc ... --qwen-rpc ... --maker maker.json --allow-launch    # the site, on 127.0.0.1:8080
```

Joining an existing launch: `hashfun node add rigcat.json --peer host:port && hashfun node up RIGCAT`.

A launch has two curves over the same coin. A block is mined on one of them and owes that curve's asset: sats on Bitcoin, or qwen on [Qwencoin](https://github.com/staccDOTsol/qwencoin). Two prices per coin; whoever mines takes the cheaper one.

The Bitcoin side (`--btc-rpc`) is a Bitcoin Core node of your own, or, with no node at all, two Electrum servers: `--btc-rpc electrums://HOST:PORT,HOST:PORT`. The Qwencoin side (`--qwen-rpc`) is a Qwencoin node. hashfun ships neither. A Qwencoin node set up by that project runs hashfun by itself: it follows the site's launches and mines their QWEN curve.

Launch files of 0.1.0 (version 2) are not read by 0.2.0: the rules changed.

What a launch is, the consensus rules, and how the binaries are built and tested: see HASHFUN.md in the repository.
