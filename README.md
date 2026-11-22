# Pysolominer 

A multi-process Bitcoin **solo miner** in pure Python (standard library only). It speaks Stratum v1, works on block templates from a solo pool such as `solo.ckpool.org`, and uses every CPU core. If one of your hashes meets the network target, the pool submits the block and the **entire reward goes to your address**.

## The idea: a free Bitcoin lottery

Solo mining is a lottery you play for free. Every hash your CPU computes is a ticket, and every ticket can win, even the very first one. About every 10 minutes the network holds a draw (a new block is found). If one of your tickets wins, you take the entire block reward, paid straight to your address.


## Features

- Stratum v1 client: subscribe, authorize, `mining.notify`, `set_difficulty`, `client.reconnect`, submit
- SHA-256 midstate optimization (header prefix hashed once per extranonce2)
- Multi-process workers with distinct extranonce2 lanes (no duplicated work)
- Immediate switch to new jobs; stale results from dead connections are dropped
- Readable stats report every 30 seconds: status, uptime, hashrate, pool/network difficulty, shares, per-worker rates
- Log file (`pysolominer_log.txt`, always next to the script, created if missing) that records everything and is cleared and restarted from the top when it reaches 1 MB (fixed)
- Automatic reconnect with exponential backoff; TLS support
- Input validation on pool messages; a bad job can't crash a worker

## Usage

Python 3.8+, no dependencies.

```bash
python pysolominer.py --url stratum+tcp://POOL_HOST:PORT --user YOUR_BTC_ADDRESS.rig1
python pysolominer.py --url stratum+tcp://POOL_HOST:PORT --user YOUR_BTC_ADDRESS --workers 4
```

`--url` is the solo pool you choose (there is no default). `--user` is your Bitcoin address, optionally followed by `.workername`. Double-check it: block rewards go exactly where this says.

### Options

| Option | Default | Meaning |
|---|---|---|
| `--url` | required | Pool, e.g. `stratum+tcp://stratum.ckpool.org:3333`,`stratum+tcp://public-pool.io:3333` |
| `--user` | required | Bitcoin address, optionally `.workername` |
| `--workers` | all CPU cores | Number of mining processes |
| `--stats-interval` | 30 | Seconds between stats reports |
| `-v` | off | Show debug lines on the console too |

## How it works

1. Pool sends job fields (prevhash, coinbase halves, merkle branch, version, nbits, ntime).
2. The miner builds `coinbase = coinb1 + extranonce1 + extranonce2 + coinb2`, folds it through the merkle branch, and assembles the 80-byte header.
3. Workers scan the 2^32 nonce space, computing double SHA-256 and comparing against the share and network targets.
4. Hits are sent with `mining.submit`; a hit that meets the network target is a block.


## Donation ⚡️

This is free and open source. If you enjoy it, or you win a block with it, an optional tip is always appreciated:

👉 BTC: bc1qjqmgkuu4qefgwpdq24dvmz60pvjnn7egvc4zke 
