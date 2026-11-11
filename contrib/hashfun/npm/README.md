# hashfun

One command for the whole stack: launch a proof-of-work coin on its own Bitcoin-fork chain, run its node, mine it, pay and prove the BTC each block owes, swap it against BTC, serve the site.

```
npm i -g hashfun            # needs Python >= 3.10; the CLI itself has no other dependencies
export HASHFUND=/path/to/hashfund   # the node binary, built from the hashfun-core repository

hashfun launch new --name "Rig Cat" --ticker RIGCAT --creator-address ... -o rigcat.json \
        --btc-rpc http://user:pass@127.0.0.1:8332 --sats-total 0.6 --creator-btc-address bc1...
hashfun node add rigcat.json
hashfun node up RIGCAT --first                      # first node of a new launch
hashfun mine RIGCAT --payout <address> --btc-rpc ... --btc-wallet miner
hashfun web --btc-rpc ... --maker maker.json --allow-launch    # the site, on 127.0.0.1:8080
```

Joining an existing launch: `hashfun node add rigcat.json --peer host:port && hashfun node up RIGCAT`.

What a launch is, the consensus rules, and how to build `hashfund`: see HASHFUN.md in the repository.
