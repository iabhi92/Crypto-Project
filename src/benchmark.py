import os
import time
import gc
import csv
from statistics import mean, stdev

from utils import N_BYTES
from lamport import Gen, Sign, Verify, GenLazy, SignLazy
from merkle_tree import MT_Construct, MT_MakePath, MT_Verify
import distributed_signing as ds

# MODE = "FULL"
MODE = "FAST"

if MODE == "FAST":
    RUNS = 30
    SETUP_RUNS = 3
    D_VALUES = [8, 16, 32]
    K_VALUES = [2, 3]
else:
    RUNS = 100
    SETUP_RUNS = 10
    D_VALUES = [8, 16, 32, 64, 128]
    K_VALUES = [2, 3, 4]

MESSAGE = b"hello world"
OUTPUT_CSV = "benchmark_results.csv"
COMPLEXITY_CSV = "complexity_comparison.csv"


def benchmark_operation(scheme, name, func, runs=RUNS):
    times = []
    gc.disable()
    try:
        for _ in range(runs):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            times.append((end - start) * 1000)
    finally:
        gc.enable()

    avg = mean(times)
    sd = stdev(times) if len(times) > 1 else 0.0
    parts = name.split()
    if len(parts) >= 2 and "=" in parts[-1]:
        operation, parameter = " ".join(parts[:-1]), parts[-1]
    else:
        operation, parameter = name, "-"

    return {
        "Scheme": scheme,
        "Operation": operation,
        "Parameter": parameter,
        "Runs": runs,
        "Average time (ms)": round(avg, 6),
        "Std ms": round(sd, 6),
    }


def benchmark_lamport():
    results = []

    kid = [0]

    def gen_once():
        Gen(kid[0])
        kid[0] += 1

    results.append(benchmark_operation("Lamport/Winternitz", "Gen", gen_once, runs=SETUP_RUNS))

    key_id = 0
    _, sk = Gen(key_id)
    r = os.urandom(N_BYTES)
    sig_r, z = Sign(MESSAGE, r, key_id, SK=sk)

    results.append(benchmark_operation("Lamport/Winternitz", "Sign",
        lambda: Sign(MESSAGE, r, key_id, SK=sk), runs=RUNS))
    results.append(benchmark_operation("Lamport/Winternitz", "Verify",
        lambda: Verify(sig_r, z, MESSAGE, key_id), runs=RUNS))

    return results


def benchmark_merkle():
    results = []

    for D in D_VALUES:
        leaves = [os.urandom(N_BYTES) for _ in range(D)]
        key_id = D // 2
        path = MT_MakePath(leaves, key_id)

        results.append(benchmark_operation("Merkle Tree", f"MT_Construct D={D}",
            lambda leaves=leaves: MT_Construct(leaves), runs=SETUP_RUNS))
        results.append(benchmark_operation("Merkle Tree", f"MT_MakePath D={D}",
            lambda leaves=leaves, key_id=key_id: MT_MakePath(leaves, key_id), runs=SETUP_RUNS))
        results.append(benchmark_operation("Merkle Tree", f"MT_Verify D={D}",
            lambda path=path, leaf=leaves[key_id]: MT_Verify(path, leaf), runs=RUNS))

    return results


def benchmark_stateful():
    results = []

    try:
        import stateful_hash as sh

        for D in D_VALUES:
            results.append(benchmark_operation("Stateful HBS", f"StatefulGen D={D}",
                lambda D=D: sh.StatefulGen(D), runs=SETUP_RUNS))

        D = max(RUNS, 128)
        sh.StatefulGen(D)

        sign_outputs = []

        def sign_once():
            key_id = len(sign_outputs)
            sign_outputs.append(sh.StatefulSign(key_id, MESSAGE))

        results.append(benchmark_operation("Stateful HBS", f"StatefulSign D={D}", sign_once, runs=RUNS))

        valid_sigs = [s for s in sign_outputs if s != () and s is not None]

        if valid_sigs:
            vcnt = [0]

            def verify_once():
                i = vcnt[0] % len(valid_sigs)
                vcnt[0] += 1
                r, path, z = valid_sigs[i]
                sh.StatefulVerify(MESSAGE, r, path, z)

            results.append(benchmark_operation("Stateful HBS", f"StatefulVerify D={D}", verify_once, runs=RUNS))

    except Exception as e:
        results.append({
            "Scheme": "Stateful HBS",
            "Operation": "Stateful benchmarks",
            "Parameter": "-",
            "Runs": 0,
            "Average time (ms)": "SKIPPED",
            "Std ms": str(e),
        })

    return results


def reset_distributed_globals():
    import shard_trustee as st

    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}
    st.keylist = {}
    st.cl_s = []


def benchmark_distributed_prf():
    results = []

    try:
        import shard_trustee as st

        for k in K_VALUES:
            n = k

            for D in D_VALUES:
                cl = [list(range(1, k + 1)) for _ in range(D)]

                def setup_once(D=D, n=n, cl=cl):
                    reset_distributed_globals()
                    seeds = {t: os.urandom(N_BYTES) for t in range(1, n + 1)}
                    provider = lambda t, kid, r, pl, sh: ds.KK_SetupContribution(seeds[t], kid, r, pl, sh)
                    _, _, init = st.ShardSetup(D, n, cl, provider)
                    for t, info in init.items():
                        st.TrusteeSetup(t, seeds[t], info["allowed_keyids"], info["path_lens"])

                results.append(benchmark_operation("PRF Distributed HBS",
                    f"ShardSetup+TrusteeSetup D={D},k={k}", setup_once, runs=SETUP_RUNS))

            for D in D_VALUES:
                sign_runs = min(RUNS, D)
                cl = [list(range(1, k + 1)) for _ in range(D)]

                reset_distributed_globals()
                seeds = {t: os.urandom(N_BYTES) for t in range(1, n + 1)}
                provider = lambda t, kid, r, pl, sh, _s=seeds: ds.KK_SetupContribution(_s[t], kid, r, pl, sh)
                _, crvs, init = st.ShardSetup(D, n, cl, provider)
                for t, info in init.items():
                    st.TrusteeSetup(t, seeds[t], info["allowed_keyids"], info["path_lens"])

                signatures = []
                count = [0]

                def sign_once():
                    key_id = count[0]
                    count[0] += 1
                    sig = st.AggregatorSign(MESSAGE, crvs, key_id)
                    signatures.append((key_id, sig))

                results.append(benchmark_operation("PRF Distributed HBS",
                    f"AggregatorSign D={D},k={k}", sign_once, runs=sign_runs))

                valid_sigs = [(kid, sig) for kid, sig in signatures if sig is not None]

                if valid_sigs:
                    vcnt = [0]

                    def verify_once():
                        i = vcnt[0] % len(valid_sigs)
                        vcnt[0] += 1
                        _, sig = valid_sigs[i]
                        r, path, z = sig
                        st.AggregatorVerify(MESSAGE, r, path, z)

                    results.append(benchmark_operation("PRF Distributed HBS",
                        f"AggregatorVerify D={D},k={k}", verify_once, runs=RUNS))

    except Exception as e:
        results.append({
            "Scheme": "PRF Distributed HBS",
            "Operation": "Distributed benchmarks",
            "Parameter": "-",
            "Runs": 0,
            "Average time (ms)": "SKIPPED",
            "Std ms": str(e),
        })

    return results


def comparison_summary():
    return [
        {"Scheme": "Lamport/Winternitz", "Operation": "Gen",         "Parameter": "single OTS key",    "Runs": "-", "Average time (ms)": "O(A * CHAIN_LEN)",                   "Std ms": "Generates all Winternitz chains"},
        {"Scheme": "Lamport/Winternitz", "Operation": "Sign",        "Parameter": "single OTS key",    "Runs": "-", "Average time (ms)": "O(A + C)",                            "Std ms": "Baseline one-time signing"},
        {"Scheme": "Lamport/Winternitz", "Operation": "Verify",      "Parameter": "single OTS key",    "Runs": "-", "Average time (ms)": "O((A + C) * CHAIN_LEN)",              "Std ms": "Reconstructs public chain tips"},
        {"Scheme": "Merkle Tree",        "Operation": "MT_Construct", "Parameter": "D leaves",          "Runs": "-", "Average time (ms)": "O(D)",                               "Std ms": "Builds the full authentication tree"},
        {"Scheme": "Merkle Tree",        "Operation": "MT_MakePath",  "Parameter": "D leaves",          "Runs": "-", "Average time (ms)": "O(D + log D)",                       "Std ms": "Constructs tree then extracts path"},
        {"Scheme": "Merkle Tree",        "Operation": "MT_Verify",    "Parameter": "D leaves",          "Runs": "-", "Average time (ms)": "O(log D)",                           "Std ms": "Verifies one authentication path"},
        {"Scheme": "Stateful HBS",       "Operation": "StatefulSign", "Parameter": "D leaves",          "Runs": "-", "Average time (ms)": "O(OTS sign + log D)",                "Std ms": "Non-distributed HBS baseline"},
        {"Scheme": "PRF Distributed HBS","Operation": "ShardSetup",   "Parameter": "D leaves, k trustees","Runs": "-","Average time (ms)": "O(D * k * (A + C) * CHAIN_LEN)",   "Std ms": "Collects trustee PRF contributions and creates CRV correction values"},
        {"Scheme": "PRF Distributed HBS","Operation": "AggregatorSign","Parameter": "D leaves, k trustees","Runs":"-","Average time (ms)": "O(k * (A + C) * CHAIN_LEN + k log D)","Std ms": "Two-round PRF-based signing"},
        {"Scheme": "PRF Distributed HBS","Operation": "AggregatorVerify","Parameter": "D leaves",       "Runs": "-", "Average time (ms)": "O(OTS verify + log D)",              "Std ms": "Same verification target as stateful HBS"},
    ]


def print_results(results):
    print("\nBenchmark results")
    print("-" * 120)
    print(f"{'Scheme':25} {'Operation':25} {'Parameter':18} {'Runs':>8} {'Average time (ms)':>20} {'Std ms':>18}")
    print("-" * 120)
    for row in results:
        print(
            f"{str(row['Scheme'])[:25]:25} "
            f"{str(row['Operation'])[:25]:25} "
            f"{str(row['Parameter'])[:18]:18} "
            f"{str(row['Runs']):>8} "
            f"{str(row['Average time (ms)']):>20} "
            f"{str(row['Std ms']):>18}"
        )
    print("-" * 120)


def save_csv(results, filename):
    fieldnames = ["Scheme", "Operation", "Parameter", "Runs", "Average time (ms)", "Std ms"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved results to {filename}")


def benchmark_lazy_chains():
    results = []
    r = os.urandom(N_BYTES)

    results.append(benchmark_operation("Lazy chain opt", "Gen  (eager, full chains)",
        lambda: Gen(0), runs=SETUP_RUNS))
    _, sk_eager = Gen(0)
    results.append(benchmark_operation("Lazy chain opt", "Sign (eager, lookup)",
        lambda: Sign(MESSAGE, r, 0, SK=sk_eager), runs=RUNS))

    results.append(benchmark_operation("Lazy chain opt", "Gen  (lazy,  seeds only)",
        lambda: GenLazy(0), runs=SETUP_RUNS))
    _, seeds = GenLazy(0)
    results.append(benchmark_operation("Lazy chain opt", "Sign (lazy,  recompute)",
        lambda: SignLazy(MESSAGE, r, 0, seeds), runs=RUNS))

    return results


def benchmark_w_sweep():
    import hashlib
    import math

    def _h(tweak, *data, nb=16):
        h = hashlib.sha256()
        for t in tweak:
            if isinstance(t, int):
                h.update(t.to_bytes(4, "big"))
            else:
                h.update(t)
        for d in data:
            h.update(d)
        return h.digest()[:nb]

    def gen_w(W):
        nb, A_w = 16, 128 // W
        C_w = math.ceil(math.log2(A_w * (2 ** W - 1)) / W)
        chain_len = 2 ** W
        SK = []
        for i in range(A_w + C_w):
            seed = os.urandom(nb)
            chain = [seed]
            for j in range(1, chain_len):
                chain.append(_h((2, i, j, 0), chain[-1], nb=nb))
            SK.append(chain)
        Y = [SK[i][-1] for i in range(A_w + C_w)]
        return _h((0, 0), *Y, nb=nb), SK

    results = []
    for W in [1, 2, 4, 8]:
        nb, A_w = 16, 128 // W
        C_w = math.ceil(math.log2(A_w * (2 ** W - 1)) / W)
        chain_len = 2 ** W
        sig_size = (A_w + C_w) * nb
        sk_size = (A_w + C_w) * chain_len * nb
        results.append(benchmark_operation(f"Winternitz W={W}",
            f"Gen sig={sig_size}B sk={sk_size}B", lambda W=W: gen_w(W), runs=SETUP_RUNS))

    return results


def benchmark_hash_backends():
    import utils as _utils

    results = []
    original = _utils.HASH_BACKEND
    for backend in ["sha256", "blake2b"]:
        _utils.HASH_BACKEND = backend
        results.append(benchmark_operation(f"Hash backend ({backend})", "Gen",
            lambda: Gen(0), runs=SETUP_RUNS))
    _utils.HASH_BACKEND = original
    return results


def benchmark_xor_optimisation():
    import timeit as _ti

    sample = [os.urandom(16) for _ in range(10)]

    def xor_loop(values):
        out = bytearray(values[0])
        for v in values[1:]:
            for i in range(len(out)):
                out[i] ^= v[i]
        return bytes(out)

    def xor_int(values):
        n = len(values[0])
        acc = int.from_bytes(values[0], "big")
        for v in values[1:]:
            acc ^= int.from_bytes(v, "big")
        return acc.to_bytes(n, "big")

    loop_us = _ti.timeit(lambda: xor_loop(sample), number=20000) / 20000 * 1e6
    int_us  = _ti.timeit(lambda: xor_int(sample),  number=20000) / 20000 * 1e6

    return [
        {"Scheme": "XOR optimisation", "Operation": "byte loop",       "Parameter": "10x16B", "Runs": 20000, "Average time (ms)": round(loop_us / 1000, 6), "Std ms": "-"},
        {"Scheme": "XOR optimisation", "Operation": "int XOR (applied)","Parameter": "10x16B", "Runs": 20000, "Average time (ms)": round(int_us / 1000, 6),  "Std ms": f"{loop_us / int_us:.1f}x faster"},
    ]


def main():
    all_results = []
    all_results.extend(benchmark_lamport())
    all_results.extend(benchmark_merkle())
    all_results.extend(benchmark_stateful())
    all_results.extend(benchmark_distributed_prf())
    all_results.extend(benchmark_lazy_chains())
    all_results.extend(benchmark_w_sweep())
    all_results.extend(benchmark_hash_backends())
    all_results.extend(benchmark_xor_optimisation())
    print_results(all_results)
    save_csv(all_results, OUTPUT_CSV)
    complexity_results = comparison_summary()
    print("\nComplexity comparison summary")
    print_results(complexity_results)
    save_csv(complexity_results, COMPLEXITY_CSV)


if __name__ == "__main__":
    main()
