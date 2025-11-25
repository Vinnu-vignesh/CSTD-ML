import pandas as pd
import numpy as np

# ---------- NAP VALIDATION ----------

def is_valid_packet(row):
    """
    Returns True if row looks like a valid packet/flow.
    Returns False if values indicate NAP (Not A Packet).
    """

    # Helper to safely get fields (returns np.nan if missing)
    def g(col):
        return row[col] if col in row.index else np.nan

    # 1) Flow Duration must be >= 0
    fd = g("Flow Duration")
    if pd.isna(fd) or fd < 0:
        return False

    # 2) Packet size sanity
    # (these names assume CIC-flow style dataset)
    size_fields = [
        "Fwd Pkt Len Max", "Fwd Pkt Len Mean",
        "Bwd Pkt Len Max", "Bwd Pkt Len Mean",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        "Pkt Size Avg"
    ]

    for col in size_fields:
        val = g(col)
        if pd.isna(val):
            continue
        if val < 0:
            return False
        # Individual packet size shouldn't exceed ~MTU (1500)
        if ("Pkt Len" in col or "Pkt Size" in col) and val > 2000:
            return False

    # Mean must not exceed max (when both present)
    fwd_mean = g("Fwd Pkt Len Mean")
    fwd_max = g("Fwd Pkt Len Max")
    if not pd.isna(fwd_mean) and not pd.isna(fwd_max):
        if fwd_mean > fwd_max + 1e-6:
            return False

    bwd_mean = g("Bwd Pkt Len Mean")
    bwd_max = g("Bwd Pkt Len Max")
    if not pd.isna(bwd_mean) and not pd.isna(bwd_max):
        if bwd_mean > bwd_max + 1e-6:
            return False

    # 3) Forward/backward packet & length consistency
    tfp = g("Tot Fwd Pkts")
    tbp = g("Tot Bwd Pkts")
    tlf = g("TotLen Fwd Pkts")
    tlb = g("TotLen Bwd Pkts")

    for v in [tfp, tbp]:
        if not pd.isna(v) and v < 0:
            return False

    # zero packets but non-zero total length is impossible
    if not pd.isna(tfp) and not pd.isna(tlf):
        if tfp == 0 and tlf > 0:
            return False
    if not pd.isna(tbp) and not pd.isna(tlb):
        if tbp == 0 and tlb > 0:
            return False

    # 4) Rate-based sanity
    fbytes_s = g("Flow Byts/s")
    fpkts_s = g("Flow Pkts/s")

    if not pd.isna(fbytes_s) and fbytes_s < 0:
        return False
    if not pd.isna(fpkts_s) and fpkts_s < 0:
        return False

    # Infinite very often means duration == 0 → treat as invalid
    if np.isinf(fpkts_s) or np.isinf(fbytes_s):
        return False

    # 5) IAT checks (basic)
    iat_fields = [
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Mean", "Fwd IAT Std",
        "Bwd IAT Mean"
    ]
    for col in iat_fields:
        val = g(col)
        if pd.isna(val):
            continue
        if val < 0:
            return False

    fim = g("Flow IAT Min")
    fix = g("Flow IAT Max")
    if not pd.isna(fim) and not pd.isna(fix):
        if fim > fix:
            return False

    # 6) TCP flag sanity (if present)
    flag_fields = ["FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
                   "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt", "ECE Flag Cnt"]
    total_pkts = 0
    if not pd.isna(tfp):
        total_pkts += tfp
    if not pd.isna(tbp):
        total_pkts += tbp

    for col in flag_fields:
        if col not in row.index:
            continue
        val = g(col)
        if pd.isna(val):
            continue
        if val < 0:
            return False
        if not pd.isna(total_pkts) and val > total_pkts:
            return False

    # Looks like a valid flow
    return True


# ---------- HEURISTIC BENIGN/MALICIOUS CLASSIFIER ----------

def classify_benign_malicious(row):
    """
    Apply simple heuristic rules to decide if a *valid* packet/flow is Benign or Malicious.
    If row is invalid, caller should label it as NAP before calling this.
    """

    def g(col):
        return row[col] if col in row.index else np.nan

    tfp = g("Tot Fwd Pkts") or 0
    tbp = g("Tot Bwd Pkts") or 0
    tlf = g("TotLen Fwd Pkts") or 0
    tlb = g("TotLen Bwd Pkts") or 0
    fd = g("Flow Duration") or 0
    fpkts_s = g("Flow Pkts/s")
    fbytes_s = g("Flow Byts/s")
    dst_port = g("Dst Port")

    suspicious_score = 0

    # Rule 1: one-sided flows (forward only, no response) → scan/flood
    if tfp >= 3 and tbp == 0:
        suspicious_score += 2

    # Rule 2: extremely high packet rate → DoS/flood
    if not pd.isna(fpkts_s) and fpkts_s > 10000:
        suspicious_score += 2

    # Rule 3: many packets but zero bytes → header-only attack
    if tfp + tbp >= 3 and tlf == 0 and tlb == 0:
        suspicious_score += 2

    # Rule 4: strong exfil ratio (huge response vs small request)
    if tlf > 0 and tlb / tlf > 50 and fd > 0:
        suspicious_score += 1

    # Rule 5: weird high ephemeral port + suspicious pattern → likely malicious
    if not pd.isna(dst_port) and dst_port >= 49152 and suspicious_score > 0:
        suspicious_score += 1

    # Decision threshold
    if suspicious_score >= 2:
        return "Malicious"
    else:
        return "Benign"


# ---------- MAIN PIPELINE ----------

def label_csv_with_predictions(input_csv, output_csv):
    df = pd.read_csv(input_csv)

    preds = []
    for _, row in df.iterrows():
        if not is_valid_packet(row):
            preds.append("NAP")
        else:
            preds.append(classify_benign_malicious(row))

    # Add new column at the end
    df["Prediction"] = preds

    df.to_csv(output_csv, index=False)
    print(f"Saved labelled file to: {output_csv}")


label_csv_with_predictions("data/newReducedDataset.csv","data/currentDataset.csv")
