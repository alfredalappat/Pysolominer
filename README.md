# pysolominer

A tiny, single-threaded **solo Bitcoin miner** in pure Python (Stratum v1, no dependencies).

Think of it as a **digital lottery**: every hash is a ticket, and one lucky hash could win an entire block. It could be your very first hash. **No fee to buy this lottery** - just run it and let it play.



## Features

- Real Stratum v1 mining with live statistics: pool / network / accepted difficulty, hashrate, shares, best share, block height
- `CONNECTION LOST` screen and automatic reconnect when the pool connection drops
- `log.txt` next to the script: created if missing, cleaned and restarted from the top at 5 MB
- Single thread, standard library only, Python 3.8+ (Windows 10+, Linux, macOS)

## Quick start

```bash
python pysolominer.py --address <YOUR_BITCOIN_ADDRESS> --url <POOL>
python pysolominer.py --selftest   # check hashing against the genesis block
```

Example pools:

```
stratum.ckpool.org:3333
stratum+tcp://public-pool.io:3333
```

## Options

| Option | Description |
|---|---|
| `--address` | Your Bitcoin address - any block reward is paid here (prompted if omitted) |
| `--url` | Pool `host:port`, with or without `stratum+tcp://` (prompted if omitted) |
| `--worker` | Optional worker name |
| `--password` | Pool password (default `x`) |
| `--selftest` | Run the built-in hash test and exit |

## Donation

If this lottery ever pays out, a donation is welcome but never required:

👉 BTC = `bc1qjqmgkuu4qefgwpdq24dvmz60pvjnn7egvc4zke`

## Disclaimer

Use at your own risk, on hardware you own, and check the terms of the pool you connect to. No reward is guaranteed.
