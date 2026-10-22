#!/usr/bin/env python3
"""Print row counts and average features per label, to check that the
scenarios actually look different from each other.

    python summarize.py data/smoke.csv
"""
import sys

import pandas as pd

from config import DATA_DIR, FEATURES
import os


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DATA_DIR,
                                                              "dataset.csv")
    df = pd.read_csv(path)
    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 20)
    print(f"{path}: {len(df)} rows\n")
    print(df["label"].value_counts().to_string(), "\n")
    print(df.groupby("label")[FEATURES].mean().round(2).to_string())


if __name__ == "__main__":
    main()
