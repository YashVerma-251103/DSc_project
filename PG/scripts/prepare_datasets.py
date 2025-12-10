import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split

# CONFIG: Adjust paths relative to where you run the script
# We assume this script runs from 'PG/scripts/' or 'PG/'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, '../outputs/cleaned_data.csv')
OUTPUT_DIR = os.path.join(BASE_DIR, '../outputs/endsem/')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def prepare_splits():
    print(f"Loading giant dataset: {INPUT_FILE} ...")
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: File not found at {INPUT_FILE}")
        return

    df = pd.read_csv(INPUT_FILE)
    
    # 1. HANDLE RARE ATTACKS (The Coreset Principle)
    # We define "Rare" as any attack appearing less than 20 times.
    # Logic: You cannot split 10 items into Train/Test/Sim effectively. 
    # Force them into Train so the model at least sees them.
    label_counts = df['Label'].value_counts()
    print("\n--- Class Distribution ---")
    print(label_counts)
    
    rare_labels = label_counts[label_counts < 20].index.tolist()
    
    if rare_labels:
        print(f"\n⚠️ FOUND RARE ATTACKS (<20 instances): {rare_labels}")
        print("Force-moving these entirely to TRAINING set...")
    
    # Split into Rare and Common
    df_rare = df[df['Label'].isin(rare_labels)]
    df_common = df[~df['Label'].isin(rare_labels)]
    
    # 2. SPLIT THE COMMON DATA
    # We want the Router Simulation to be diverse.
    # Stratified Split ensures the Router sees the same % of DDoS as the Training set.
    
    # A. Extract 10% for the "Router Traffic" (Untouched by Training)
    # This is the "New Packet" stream.
    df_modeling, df_simulation = train_test_split(
        df_common, 
        test_size=0.10, 
        random_state=42, 
        stratify=df_common['Label'] 
    )
    
    # B. Split the remaining 90% into Train (70%) and Test (20%)
    # Math: 0.22 of the remaining 90% is approx 20% of the total original.
    df_train_common, df_test = train_test_split(
        df_modeling,
        test_size=0.22, 
        random_state=42,
        stratify=df_modeling['Label']
    )
    
    # 3. CONSTRUCT FINAL SETS
    # Train = Common Train + ALL Rare Rows
    df_train = pd.concat([df_train_common, df_rare])
    
    print("\n--- SPLIT SUMMARY ---")
    print(f"Training Set   : {len(df_train)} rows (Contains ALL rare attacks)")
    print(f"Test Set       : {len(df_test)} rows (For Evaluation Metrics)")
    print(f"Router Sim Set : {len(df_simulation)} rows (For Docker Simulation)")
    
    # 4. SAVE ARTIFACTS
    # Parquet for Model Training (Fast/Small)
    df_train.to_parquet(os.path.join(OUTPUT_DIR, 'train.parquet'))
    df_test.to_parquet(os.path.join(OUTPUT_DIR, 'test.parquet'))
    
    # CSV for Router Simulation (Simulates raw text logs)
    # We cap this at 50k rows to keep the Docker container light (~5-10MB)
    if len(df_simulation) > 50000:
        df_simulation = df_simulation.sample(n=50000, random_state=42)
        
    sim_path = os.path.join(OUTPUT_DIR, 'router_traffic.csv')
    df_simulation.to_csv(sim_path, index=False)
    
    print(f"\n✅ Artifacts saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    prepare_splits()