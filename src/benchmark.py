import os
import time
import gc
import csv
from statistics import mean, stdev

from utils import N_BYTES
from lamport import Gen, Sign, Verify
from merkle_tree import MT_Construct, MT_MakePath, MT_Verify
import distributed_signing as ds

# Benchmark mode:
# FAST is useful for local debugging.
# FULL is used for the final report / marking.

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


def split_operation_name(name):
    parts = name.split()
    if len(parts) >= 2 and "=" in parts[-1]:
        return " ".join(parts[:-1]), parts[-1]
    return name, "-"


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
    operation, parameter = split_operation_name(name)

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

    key_counter = {"value": 0}

    def gen_once():
        kid = key_counter["value"]
        key_counter["value"] += 1
        Gen(kid)

    results.append(
        benchmark_operation(
            "Lamport/Winternitz",
            "Gen",
            gen_once,
            runs=SETUP_RUNS,
        )
    )

    key_id = 0
    _, sk = Gen(key_id)
    r = os.urandom(N_BYTES)
    sig_r, z = Sign(MESSAGE, r, key_id, SK=sk)

    def sign_once():
        Sign(MESSAGE, r, key_id, SK=sk)

    def verify_once():
        Verify(sig_r, z, MESSAGE, key_id)

    results.append(
        benchmark_operation(
            "Lamport/Winternitz",
            "Sign",
            sign_once,
            runs=RUNS,
        )
    )

    results.append(
        benchmark_operation(
            "Lamport/Winternitz",
            "Verify",
            verify_once,
            runs=RUNS,
        )
    )

    return results


def benchmark_merkle():
    results = []

    for D in D_VALUES:
        leaves = [os.urandom(N_BYTES) for _ in range(D)]
        key_id = D // 2
        path = MT_MakePath(leaves, key_id)

        def construct_once(leaves=leaves):
            MT_Construct(leaves)

        def make_path_once(leaves=leaves, key_id=key_id):
            MT_MakePath(leaves, key_id)

        def verify_once(path=path, leaf=leaves[key_id]):
            MT_Verify(path, leaf)

        results.append(
            benchmark_operation(
                "Merkle Tree",
                f"MT_Construct D={D}",
                construct_once,
                runs=SETUP_RUNS,
            )
        )

        results.append(
            benchmark_operation(
                "Merkle Tree",
                f"MT_MakePath D={D}",
                make_path_once,
                runs=SETUP_RUNS,
            )
        )

        results.append(
            benchmark_operation(
                "Merkle Tree",
                f"MT_Verify D={D}",
                verify_once,
                runs=RUNS,
            )
        )

    return results


def benchmark_stateful():
    results = []

    try:
        import stateful_hash as sh

        for D in D_VALUES:
            def gen_once(D=D):
                sh.StatefulGen(D)

            results.append(
                benchmark_operation(
                    "Stateful HBS",
                    f"StatefulGen D={D}",
                    gen_once,
                    runs=SETUP_RUNS,
                )
            )

        D = max(RUNS, 128)
        sh.StatefulGen(D)

        sign_outputs = []

        def sign_once():
            key_id = len(sign_outputs)
            sign_outputs.append(sh.StatefulSign(key_id, MESSAGE))

        results.append(
            benchmark_operation(
                "Stateful HBS",
                f"StatefulSign D={D}",
                sign_once,
                runs=RUNS,
            )
        )

        valid_sigs = [s for s in sign_outputs if s != () and s is not None]

        if valid_sigs:
            verify_counter = {"value": 0}

            def verify_once():
                i = verify_counter["value"] % len(valid_sigs)
                verify_counter["value"] += 1
                r, path, z = valid_sigs[i]
                sh.StatefulVerify(MESSAGE, r, path, z)

            results.append(
                benchmark_operation(
                    "Stateful HBS",
                    f"StatefulVerify D={D}",
                    verify_once,
                    runs=RUNS,
                )
            )

    except Exception as e:
        results.append(
            {
                "Scheme": "Stateful HBS",
                "Operation": "Stateful benchmarks",
                "Parameter": "-",
                "Runs": 0,
                "Average time (ms)": "SKIPPED",
                "Std ms": str(e),
            }
        )

    return results


def reset_distributed_globals():
    import distributed_signing as ds
    import shard_trustee as st

    ds.K = {}
    ds.used_keys = {}
    ds.current = {}
    ds.trustee_path_lens = {}

    st.keylist = {}
    st.cl_s = []


def make_trustee_seeds(n):
    return {t: os.urandom(N_BYTES) for t in range(1, n + 1)}


def make_contribution_provider(trustee_seeds):
    def contribution_provider(t, key_id, r, path_lens, sk_shape):
        return ds.KK_SetupContribution(
            trustee_seeds[t],
            key_id,
            r,
            path_lens,
            sk_shape,
        )

    return contribution_provider


def initialise_trustees(st, trustee_init, trustee_seeds):
    for t, init in trustee_init.items():
        st.TrusteeSetup(
            t,
            trustee_seeds[t],
            init["allowed_keyids"],
            init["path_lens"],
        )


def benchmark_distributed_prf():
    """
    Benchmark the Full Project-style PRF-based distributed signing flow.
    Varies:
    - k: number of trustees in each signing coalition
    - D: number of one-time signing keys / Merkle leaves
    """
    results = []

    try:
        import shard_trustee as st

        for k in K_VALUES:
            n = k

            # Benchmark setup across both D and k
            for D in D_VALUES:
                cl = [list(range(1, k + 1)) for _ in range(D)]

                def setup_once(D=D, n=n, cl=cl):
                    reset_distributed_globals()
                    trustee_seeds = make_trustee_seeds(n)
                    provider = make_contribution_provider(trustee_seeds)
                    _, _, trustee_init = st.ShardSetup(D, n, cl, provider)
                    initialise_trustees(st, trustee_init, trustee_seeds)

                results.append(
                    benchmark_operation(
                        "PRF Distributed HBS",
                        f"ShardSetup+TrusteeSetup D={D},k={k}",
                        setup_once,
                        runs=SETUP_RUNS,
                    )
                )

            # Benchmark signing and verification across both D and k
            for D in D_VALUES:
                sign_runs = min(RUNS, D)
                cl = [list(range(1, k + 1)) for _ in range(D)]

                reset_distributed_globals()
                trustee_seeds = make_trustee_seeds(n)
                provider = make_contribution_provider(trustee_seeds)
                _, crvs, trustee_init = st.ShardSetup(D, n, cl, provider)
                initialise_trustees(st, trustee_init, trustee_seeds)

                signatures = []
                sign_counter = {"value": 0}

                def sign_once():
                    key_id = sign_counter["value"]
                    sign_counter["value"] += 1
                    sig = st.AggregatorSign(MESSAGE, crvs, key_id)
                    signatures.append((key_id, sig))

                results.append(
                    benchmark_operation(
                        "PRF Distributed HBS",
                        f"AggregatorSign D={D},k={k}",
                        sign_once,
                        runs=sign_runs,
                    )
                )

                valid_sigs = [
                    (key_id, sig)
                    for key_id, sig in signatures
                    if sig is not None
                ]

                if valid_sigs:
                    verify_counter = {"value": 0}

                    def verify_once():
                        i = verify_counter["value"] % len(valid_sigs)
                        verify_counter["value"] += 1
                        _, sig = valid_sigs[i]
                        r, path, z = sig
                        st.AggregatorVerify(MESSAGE, r, path, z)

                    results.append(
                        benchmark_operation(
                            "PRF Distributed HBS",
                            f"AggregatorVerify D={D},k={k}",
                            verify_once,
                            runs=RUNS,
                        )
                    )

    except Exception as e:
        results.append(
            {
                "Scheme": "PRF Distributed HBS",
                "Operation": "Distributed benchmarks",
                "Parameter": "-",
                "Runs": 0,
                "Average time (ms)": "SKIPPED",
                "Std ms": str(e),
            }
        )

    return results


def comparison_summary():
    return [
        {
            "Scheme": "Lamport/Winternitz",
            "Operation": "Gen",
            "Parameter": "single OTS key",
            "Runs": "-",
            "Average time (ms)": "O(A * CHAIN_LEN)",
            "Std ms": "Generates all Winternitz chains",
        },
        {
            "Scheme": "Lamport/Winternitz",
            "Operation": "Sign",
            "Parameter": "single OTS key",
            "Runs": "-",
            "Average time (ms)": "O(A + C)",
            "Std ms": "Baseline one-time signing",
        },
        {
            "Scheme": "Lamport/Winternitz",
            "Operation": "Verify",
            "Parameter": "single OTS key",
            "Runs": "-",
            "Average time (ms)": "O((A + C) * CHAIN_LEN)",
            "Std ms": "Reconstructs public chain tips",
        },
        {
            "Scheme": "Merkle Tree",
            "Operation": "MT_Construct",
            "Parameter": "D leaves",
            "Runs": "-",
            "Average time (ms)": "O(D)",
            "Std ms": "Builds the full authentication tree",
        },
        {
            "Scheme": "Merkle Tree",
            "Operation": "MT_MakePath",
            "Parameter": "D leaves",
            "Runs": "-",
            "Average time (ms)": "O(D + log D)",
            "Std ms": "Constructs tree then extracts path",
        },
        {
            "Scheme": "Merkle Tree",
            "Operation": "MT_Verify",
            "Parameter": "D leaves",
            "Runs": "-",
            "Average time (ms)": "O(log D)",
            "Std ms": "Verifies one authentication path",
        },
        {
            "Scheme": "Stateful HBS",
            "Operation": "StatefulSign",
            "Parameter": "D leaves",
            "Runs": "-",
            "Average time (ms)": "O(OTS sign + log D)",
            "Std ms": "Non-distributed HBS baseline",
        },
        {
            "Scheme": "PRF Distributed HBS",
            "Operation": "ShardSetup",
            "Parameter": "D leaves, k trustees",
            "Runs": "-",
            "Average time (ms)": "O(D * k * (A + C) * CHAIN_LEN)",
            "Std ms": "Collects trustee PRF contributions and creates CRV correction values",
        },
        {
            "Scheme": "PRF Distributed HBS",
            "Operation": "AggregatorSign",
            "Parameter": "D leaves, k trustees",
            "Runs": "-",
            "Average time (ms)": "O(k * (A + C) * CHAIN_LEN + k log D)",
            "Std ms": "Two-round PRF-based signing",
        },
        {
            "Scheme": "PRF Distributed HBS",
            "Operation": "AggregatorVerify",
            "Parameter": "D leaves",
            "Runs": "-",
            "Average time (ms)": "O(OTS verify + log D)",
            "Std ms": "Same verification target as stateful HBS",
        },
    ]


def print_results(results):
    print("\nBenchmark results")
    print("-" * 120)
    print(
        f"{'Scheme':25} "
        f"{'Operation':25} "
        f"{'Parameter':18} "
        f"{'Runs':>8} "
        f"{'Average time (ms)':>20} "
        f"{'Std ms':>18}"
    )
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
    fieldnames = [
        "Scheme",
        "Operation",
        "Parameter",
        "Runs",
        "Average time (ms)",
        "Std ms",
    ]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nSaved results to {filename}")


def main():
    all_results = []
    all_results.extend(benchmark_lamport())
    all_results.extend(benchmark_merkle())
    all_results.extend(benchmark_stateful())
    all_results.extend(benchmark_distributed_prf())
    print_results(all_results)
    save_csv(all_results, OUTPUT_CSV)
    complexity_results = comparison_summary()
    print("\nComplexity comparison summary")
    print_results(complexity_results)
    save_csv(complexity_results, COMPLEXITY_CSV)


if __name__ == "__main__":
    main()
