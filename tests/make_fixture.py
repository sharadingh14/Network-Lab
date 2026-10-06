"""Writes small SYNTHETIC day files with the CSE-CIC-IDS2018 (Kaggle) column layout.
Used only by the smoke test; never used for any reported result."""
import os
import numpy as np
import pandas as pd

COLS = ("Dst Port,Protocol,Timestamp,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,"
        "Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,Bwd Pkt Len Min,"
        "Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow Byts/s,Flow Pkts/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,"
        "Flow IAT Min,Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Tot,Bwd IAT Mean,"
        "Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,"
        "Fwd Header Len,Bwd Header Len,Fwd Pkts/s,Bwd Pkts/s,Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,"
        "Pkt Len Var,FIN Flag Cnt,SYN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,ACK Flag Cnt,URG Flag Cnt,CWE Flag Count,"
        "ECE Flag Cnt,Down/Up Ratio,Pkt Size Avg,Fwd Seg Size Avg,Bwd Seg Size Avg,Fwd Byts/b Avg,Fwd Pkts/b Avg,"
        "Fwd Blk Rate Avg,Bwd Byts/b Avg,Bwd Pkts/b Avg,Bwd Blk Rate Avg,Subflow Fwd Pkts,Subflow Fwd Byts,"
        "Subflow Bwd Pkts,Subflow Bwd Byts,Init Fwd Win Byts,Init Bwd Win Byts,Fwd Act Data Pkts,Fwd Seg Size Min,"
        "Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label").split(",")
DAYS = {"02-14-2018": ["FTP-BruteForce", "SSH-Bruteforce"], "02-15-2018": ["DoS attacks-GoldenEye"],
        "02-16-2018": ["DoS attacks-Hulk"], "02-21-2018": ["DDOS attack-HOIC"],
        "02-22-2018": ["Brute Force -Web"], "03-02-2018": ["Bot"]}
PORT = {"FTP-BruteForce": 21, "SSH-Bruteforce": 22, "DoS attacks-GoldenEye": 80, "DoS attacks-Hulk": 80,
        "DDOS attack-HOIC": 80, "Brute Force -Web": 80, "Bot": 8080}

rng = np.random.default_rng(0)
os.makedirs("data/fixture", exist_ok=True)
for di, (day, labels) in enumerate(DAYS.items()):
    rows = []
    for lab in ["Benign"] + labels:
        n = 4000 if lab == "Benign" else 1200
        base = rng.lognormal(3 + (sum(map(ord, lab)) % 5), 1.0, size=(n, len(COLS) - 4))
        df = pd.DataFrame(base, columns=COLS[3:-1])
        df["Dst Port"] = rng.choice([443, 53, 80, 3389], n) if lab == "Benign" else PORT[lab]
        df["Protocol"] = 6
        m, d, y = day.split("-")
        df["Timestamp"] = [f"{d}/{m}/{y} {8 + i * 8 // n:02d}:{(i * 7) % 60:02d}:{i % 60:02d}" for i in range(n)]
        df["Label"] = lab
        rows.append(df)
    pd.concat(rows)[COLS].sample(frac=1, random_state=di).to_csv(f"data/fixture/{day}.csv", index=False)
print("fixture written")
