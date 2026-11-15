"""hashfun launch tool: create a launch descriptor (mines its genesis), inspect
one, and write a node config. Same math as the node, implemented independently."""
import argparse
import json
import os
import sys
import time

from . import descriptor as D
from . import meta as M
from .crypto import sha256d
from .ser import address_to_script, bits_to_target, work_from_bits

COIN = D.COIN


def fmt_hashes(h: float) -> str:
    for unit, v in (("EH", 1e18), ("PH", 1e15), ("TH", 1e12), ("GH", 1e9), ("MH", 1e6), ("kH", 1e3)):
        if h >= v:
            return f"{h / v:.3g} {unit}"
    return f"{h:.3g} H"


def curve_table(d: D.Launch, points=11):
    """One curve from empty to sold out (both have this shape), with what a coin costs at each point on
    either quote: sats per coin on the BTC curve, qwen base units per coin on the QWEN curve."""
    rows = []
    wg = d.graduation_work
    for i in range(points):
        w = wg * i // (points - 1)
        rows.append({"work": w, "supply": d.curve_supply(w), "progress": d.curve_supply(w) / d.graduation_tokens,
                     "hashes_per_coin": d.hashes_per_coin(w), "sats_per_coin": d.price_per_coin(w, "btc"),
                     "qwen_per_coin": d.price_per_coin(w, "qwen")})
    return rows


def _anchor_info(d: D.Launch, quote: str) -> dict:
    height, header, period = d.anchor(quote)
    return {"height": height, "block": sha256d(header)[::-1].hex(), "period_time": period,
            "regtest": d.quote_regtest(quote)}


def _leg_info(d: D.Launch, quote: str) -> dict:
    """One curve's money side: what it owes in all if it sells out, and its price point at both ends."""
    num, shift = d.owed_rate(quote)
    return {"num": num, "shift": shift, "total": d.leg_total(quote), "min_payment": d.min_payment(quote),
            "confs": d.confs(quote), "confs_hours": round(d.confs(quote) * 600 / 3600, 2),
            "creator_script": d.creator_quote_script(quote).hex(),
            "start_price_per_coin": d.price_per_coin(0, quote),
            "graduation_price_per_coin": d.price_per_coin(d.graduation_work, quote)}


def info(d: D.Launch) -> dict:
    return {
        "launch_id": d.id_hex, "genesis_hash": d.genesis_hash, "genesis_valid": d.genesis_valid(),
        "name": d.name, "ticker": d.ticker, "hrp": d.hrp, "chain_id": d.chain_id, "magic": d.magic.hex(),
        "p2p_port": d.p2p, "rpc_port": d.rpc, "datadir": d.datadir_name,
        # Each of the two curves (BTC, QWEN) has this shape. The first to sell out graduates the launch.
        "curve": {"virtual_work": d.virtual_work, "virtual_tokens": d.virtual_tokens,
                  "graduation_tokens": d.graduation_tokens, "graduation_work": d.graduation_work,
                  "graduation_hashes_human": fmt_hashes(d.graduation_work),
                  "start_price_hashes_per_coin": d.hashes_per_coin(0),
                  "graduation_price_hashes_per_coin": d.hashes_per_coin(d.graduation_work)},
        # What a block on each curve owes, in base units of its own asset (sats of BTC, sats of QWEN),
        # and the QWEN price the two starting price points stand for (sats per whole QWEN).
        "legs": {"btc": _leg_info(d, "btc"), "qwen": _leg_info(d, "qwen"),
                 "implied_qwen_sats_at_start": d.implied_qwen_sats(0, 0)},
        "tail": {"reward": d.tail_reward, "halving_interval": d.tail_halving_interval,
                 "total": d.tail_reward * d.tail_halving_interval * 2},
        "creator": {"script": d.creator_script.hex(), "fee_bps": d.creator_fee_bps},
        "difficulty": {"pow_limit_bits": f"{d.pow_limit_bits:08x}", "target_spacing": d.target_spacing,
                       "lwma_window": d.lwma_window, "ftl": d.ftl},
        # The Bitcoin block and the Qwencoin block the launch is anchored to. A launch file can say
        # anything here that looks like a header: `info --btc-rpc / --qwen-rpc` asks a node of that
        # chain whether it is true (descriptor.check_anchor, check_qwen_anchor).
        "btc_anchor": _anchor_info(d, "btc"),
        "qwen_anchor": _anchor_info(d, "qwen"),
        "meta": _meta_info(d),
    }


def _meta_info(d: D.Launch) -> dict:
    """What the launch commits to, and whether this file carries the matching bytes."""
    if not any(d.meta):
        return {"hash": None}
    try:
        m = M.check(d)
    except M.MetaError as e:
        return {"hash": d.meta.hex(), "verified": False, "error": str(e)}
    if m is None:
        return {"hash": d.meta.hex(), "verified": False, "error": "this file does not carry the metadata"}
    return {"hash": d.meta.hex(), "verified": True, "description": m.description, "image_type": m.image_type,
            "image_bytes": len(m.image), **{k: getattr(m, k) for k in M.LINKS if getattr(m, k)}}


def node_conf(d: D.Launch, descriptor_path: str, rpcuser="hashfun", rpcpassword=None, extra=None) -> str:
    rpcpassword = rpcpassword or os.urandom(16).hex()
    lines = [f"# hashfun launch {d.ticker} ({d.id_hex[:8]})", f"launch={os.path.abspath(descriptor_path)}", "server=1",
             "txindex=1", "[launch]", f"rpcuser={rpcuser}", f"rpcpassword={rpcpassword}", f"port={d.p2p}",
             f"rpcport={d.rpc}"]
    for s in d.seeds:
        lines.append(f"seednode={s}")
    for k, v in (extra or {}).items():
        lines.append(f"{k}={v}")
    return "\n".join(lines) + "\n"


def _load(ap, path: str) -> D.Launch:
    """The launch file at `path`, or the tool's usual error exit saying what is wrong with it."""
    try:
        return D.load(path)
    except OSError as e:
        ap.error(f"{path}: {e.strerror or e}")
    except D.DescriptorError as e:
        ap.error(f"{path}: {e}")


def _chain_rpc(ap, a, quote: str):
    """The RPC of the Bitcoin (--btc-rpc) or the Qwencoin (--qwen-rpc) node named on the command line.
    Bitcoin may also be electrums://HOST:PORT,HOST:PORT: Electrum servers, no node (hashfun.btclight)."""
    from .btclight import connect, is_light_url
    from .rpc import RPC
    try:
        if quote == "btc" and is_light_url(a.btc_rpc):
            return connect(a.btc_rpc)
        return RPC(getattr(a, f"{quote}_rpc"), cookie_file=getattr(a, f"{quote}_cookie"))
    except (OSError, ValueError) as e:  # the cookie file, or a URL that is not one
        ap.error(f"--{quote}-rpc: {e}")


def _btc_rpc(ap, a):
    return _chain_rpc(ap, a, "btc")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hashfun-launch", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("new", help="create a descriptor and mine its genesis")
    p.add_argument("--name", required=True)
    p.add_argument("--ticker", required=True)
    p.add_argument("--creator-address", required=True, help="bech32 address with the launch's hrp")
    p.add_argument("--hrp")
    p.add_argument("--graduation-hashes", type=float, default=1e22, help="total hash to graduate (default 1e22)")
    p.add_argument("--supply", type=int, default=D.DEFAULT_SUPPLY_COINS,
                   help="virtual token supply of each curve (coins). Each of the two curves can mint 73.91%% of it and "
                        "the tail the rest, so at most 1.7391 times this ever exists, which has to stay within 21M "
                        "(default 12,000,000, the largest round number that does)")
    p.add_argument("--fee-bps", type=int, default=100)
    p.add_argument("--spacing", type=int, default=5)
    p.add_argument("--window", type=int, default=90)
    p.add_argument("--btc-anchor", metavar="HEIGHT:HEADERHEX[:PERIODTIME]",
                   help="the recent Bitcoin block the launch is anchored to (it proves the launch was not mined before "
                        "that block): its height, its 80-byte header in hex, and the time of the first block of its "
                        "2016-block difficulty period, which is block HEIGHT - HEIGHT %% 2016. PERIODTIME may be left "
                        "out only when HEIGHT is a multiple of 2016 (that block opens its period, so the time is its "
                        "own); anywhere else leaving it out is an error. --btc-rpc alone takes all three from a "
                        "Bitcoin node, which is the easy way; given with --btc-anchor it checks the anchor against the node")
    p.add_argument("--btc-rpc", help="Bitcoin Core RPC URL (or electrums://HOST:PORT,HOST:PORT): take the anchor from its "
                                     "chain (6 blocks deep), or, with --btc-anchor, check that anchor against its chain")
    p.add_argument("--btc-cookie", help="Bitcoin Core .cookie file, if the URL has no user:pass")
    p.add_argument("--sats-total", type=float, metavar="BTC",
                   help="sats leg: total BTC the curve owes holders/creator/dev (needs an anchor and --creator-btc-address)")
    p.add_argument("--creator-btc-address", help="Bitcoin address for the creator's 10%% of the sats leg")
    p.add_argument("--btc-regtest", action="store_true", help="sats leg follows a regtest Bitcoin (test fleets)")
    p.add_argument("--btc-hrp", default="bc", help="bech32 prefix of the Bitcoin network (bc, tb, bcrt)")
    p.add_argument("--qwen-anchor", metavar="HEIGHT:HEADERHEX[:PERIODTIME]",
                   help="the recent Qwencoin block the QWEN leg is anchored to, given like --btc-anchor. --qwen-rpc alone "
                        "takes all three from a Qwencoin node; given with --qwen-anchor it checks the anchor against the node")
    p.add_argument("--qwen-rpc", help="Qwencoin node RPC URL (qwencoind speaks bitcoin-cli's RPC): take the anchor from its "
                                      "chain (6 blocks deep), or, with --qwen-anchor, check that anchor against its chain")
    p.add_argument("--qwen-cookie", help="the Qwencoin node's .cookie file, if the URL has no user:pass")
    p.add_argument("--qwen-total", type=float, metavar="QWEN",
                   help="QWEN leg: total QWEN the QWEN curve owes holders/creator/dev if it sells out (needs an anchor "
                        "and --creator-qwen-address). With --sats-total it sets the coin's two starting price points, "
                        "and so the QWEN price the launch opens at")
    p.add_argument("--creator-qwen-address", help="Qwencoin address for the creator's 10%% of the QWEN leg (on Qwencoin's "
                                                  "main network an address is the same string as the Bitcoin address of "
                                                  "the same key)")
    p.add_argument("--qwen-confs", type=int, metavar="N",
                   help="Qwencoin confirmations a QWEN payment needs before its proof counts (1..1008). Default: enough "
                        "that faking the whole leg costs more Qwencoin blocks than paying it: ceil(1.25 * QWEN / 50), at "
                        "least 6; a --qwen-total that 1008 do not cover is refused unless this is given")
    p.add_argument("--qwen-regtest", action="store_true",
                   help="QWEN leg follows a regtest Qwencoin (test fleets). --test alone means this too; --test with "
                        "--qwen-rpc or --qwen-anchor is a test launch whose QWEN leg follows the real Qwencoin, unless "
                        "this is given")
    p.add_argument("--qwen-hrp", help="bech32 prefix of the Qwencoin network (default: --btc-hrp; Qwencoin uses Bitcoin's)")
    p.add_argument("--pow-limit", default="1e0fffff", help="difficulty floor (compact); LWMA ramps up from here")
    p.add_argument("--tail-years", type=int, default=8)
    p.add_argument("--test", action="store_true",
                   help="test launch: mockable time, nonstandard txs allowed, the sats leg on a regtest Bitcoin, and the "
                        "QWEN leg on a regtest Qwencoin unless a Qwencoin is named (see --qwen-regtest)")
    p.add_argument("--seed", action="append", default=[])
    p.add_argument("--image", metavar="FILE", help="the coin's picture: PNG, JPEG, GIF or WebP, at most 64 KB. "
                                                   "Its hash goes into the launch id; it can never be changed")
    p.add_argument("--description", default="", help="a line or two about the coin (at most 500 bytes)")
    p.add_argument("--website", default="", help="https:// link")
    p.add_argument("--x", default="", help="https:// link to the coin's X account")
    p.add_argument("--telegram", default="", help="https:// link")
    p.add_argument("-o", "--out", required=True)
    p = sub.add_parser("info")
    p.add_argument("descriptor")
    p.add_argument("--curve", action="store_true")
    p.add_argument("--btc-rpc", help="Bitcoin Core RPC URL: check the launch's Bitcoin anchor against its chain (do this "
                                     "before mining or joining a launch whose file came from someone else)")
    p.add_argument("--btc-cookie", help="Bitcoin Core .cookie file, if the URL has no user:pass")
    p.add_argument("--qwen-rpc", help="Qwencoin node RPC URL: check the launch's Qwencoin anchor against its chain. "
                                      "Neither this tool nor the launch file can tell that the anchor is a Qwencoin "
                                      "block at all without one")
    p.add_argument("--qwen-cookie", help="the Qwencoin node's .cookie file, if the URL has no user:pass")
    p = sub.add_parser("conf")
    p.add_argument("descriptor")
    p.add_argument("--rpcuser", default="hashfun")
    p.add_argument("--rpcpassword")
    a = ap.parse_args(argv)

    if a.cmd == "new":
        hrp = a.hrp or a.ticker.lower()
        creator = address_to_script(a.creator_address, hrp)
        regtest = a.test or a.btc_regtest
        # The QWEN leg follows a regtest Qwencoin when that is said, or in a test launch that names no
        # Qwencoin at all (no node, no anchor): --test fills that leg with regtest values. A test launch
        # that names one has a real QWEN leg, unless it says --qwen-regtest.
        qregtest = a.qwen_regtest or (a.test and not a.qwen_rpc and not a.qwen_anchor)
        need_late = not (regtest and qregtest)  # the legs and anchors are filled in below, then validated
        try:
            d = D.make(a.name, a.ticker, creator, int(a.graduation_hashes), supply_coins=a.supply, _validate=not need_late,
                       creator_fee_bps=a.fee_bps, target_spacing=a.spacing, lwma_window=a.window, test=a.test,
                       tail_years=a.tail_years, pow_limit_bits=int(a.pow_limit, 16), hrp=hrp,
                       btc_anchor=a.btc_anchor.split(":") if a.btc_anchor else None, btc_regtest=regtest,
                       qwen_anchor=a.qwen_anchor.split(":") if a.qwen_anchor else None, qwen_regtest=qregtest,
                       sats_total=int(round(a.sats_total * D.COIN)) if a.sats_total else None,
                       qwen_total=int(round(a.qwen_total * D.COIN)) if a.qwen_total else None, qwen_confs=a.qwen_confs)
        except D.DescriptorError as e:
            which = "btc" if str(e).startswith("btc anchor") else "qwen" if str(e).startswith("qwen anchor") else None
            ap.error(f"--{which}-anchor HEIGHT:HEADERHEX[:PERIODTIME]: {e}" if which else str(e))
        d.seeds = a.seed
        try:
            image = open(a.image, "rb").read() if a.image else b""
            M.attach(d, M.from_image(image, description=a.description, website=a.website, x=a.x, telegram=a.telegram))
        except (OSError, M.MetaError) as e:
            ap.error(str(e))
        for quote, chain, given, check, take in (
                ("btc", "Bitcoin", a.btc_anchor, D.check_anchor, D.btc_anchor_from_rpc),
                ("qwen", "Qwencoin", a.qwen_anchor, D.check_qwen_anchor, D.qwen_anchor_from_rpc)):
            if getattr(a, f"{quote}_rpc"):
                node = _chain_rpc(ap, a, quote)
                try:
                    if given:  # an anchor was given: ask the node whether it is true
                        check(d, node)
                    else:
                        h, hdr, period = take(node)
                        setattr(d, f"{quote}_anchor_height", h)
                        setattr(d, f"{quote}_anchor_header", bytes.fromhex(hdr))
                        setattr(d, f"{quote}_anchor_period_time", period)
                except D.DescriptorError as e:
                    ap.error(str(e))
                except Exception as e:  # the node did not answer, or not with a block
                    ap.error(f"--{quote}-rpc: could not read the anchor from the {chain} node: {e}")
            elif given and not d.quote_regtest(quote):
                print(f"note: the {chain} anchor was taken as given. Add --{quote}-rpc URL to check it against a {chain} "
                      f"node: with a wrong height or period start the launch stops accepting {chain} headers at the next "
                      "retarget, and nothing on it can settle after that.", file=sys.stderr)
        if a.creator_btc_address:
            d.creator_btc_script = address_to_script(a.creator_btc_address, a.btc_hrp)
        if a.creator_qwen_address:
            d.creator_qwen_script = address_to_script(a.creator_qwen_address, a.qwen_hrp or a.btc_hrp)
        try:
            D.validate(d)
        except D.DescriptorError as e:
            missing = str(e).startswith(("sats_num", "btc_anchor_header: required", "creator_btc_script: required",
                                         "qwen_num", "qwen_anchor_header: required", "creator_qwen_script: required"))
            ap.error(f"{e}. Every launch needs --sats-total, --creator-btc-address and a Bitcoin anchor "
                     "(--btc-rpc or --btc-anchor), and --qwen-total, --creator-qwen-address and a Qwencoin anchor "
                     "(--qwen-rpc or --qwen-anchor); --test fills regtest defaults." if missing else str(e))
        print(f"qwen_confs {d.qwen_confs}: a payment on Qwencoin counts once it is {d.qwen_confs} blocks deep, about "
              f"{d.qwen_confs * D.QWEN_BLOCK_SECONDS / 3600:.1f} hours; settle_deadline {d.settle_deadline} launch blocks, "
              f"about {d.settle_deadline * d.target_spacing / 3600:.1f} hours to pay and prove what a block owes",
              file=sys.stderr)
        t0 = time.time()
        expected = 2**256 / (bits_to_target(d.pow_limit_bits) + 1)
        print(f"mining genesis (~{fmt_hashes(expected)} expected)...", file=sys.stderr)
        d.grind_genesis(lambda n: print(f"  nonce {n:,}", file=sys.stderr))
        print(f"genesis nonce {d.genesis_nonce} in {time.time() - t0:.1f}s", file=sys.stderr)
        with open(a.out, "w") as f:
            f.write(d.dumps())
        print(json.dumps(info(d), indent=2))
    elif a.cmd == "info":
        d = _load(ap, a.descriptor)
        out = info(d)
        for quote, check in (("btc", D.check_anchor), ("qwen", D.check_qwen_anchor)):
            if getattr(a, f"{quote}_rpc"):
                try:
                    check(d, _chain_rpc(ap, a, quote))
                except D.DescriptorError as e:
                    ap.error(f"{a.descriptor}: {e}")
                out[f"{quote}_anchor"]["checked"] = True  # the block at that height on the node's chain, period start and all
        if a.curve:
            out["curve_table"] = curve_table(d)
        print(json.dumps(out, indent=2))
    elif a.cmd == "conf":
        d = _load(ap, a.descriptor)
        sys.stdout.write(node_conf(d, a.descriptor, a.rpcuser, a.rpcpassword))


if __name__ == "__main__":
    main()
