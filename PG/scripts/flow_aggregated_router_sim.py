import time
import sys
import os
import psutil
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Get the directory where THIS script is located (/app/scripts/ or .../PG/scripts/)
print(f"[{datetime.now()}] 📂 Base Directory: {BASE_DIR}")
MODEL_PATH = os.path.join(BASE_DIR,'../outputs/endsem/router_model_coreset_5pct.joblib')
SCALER_PATH = os.path.join(BASE_DIR,'../outputs/endsem/router_scaler.joblib')
DATA_PATH = os.path.join(BASE_DIR,'../outputs/cleaned_data.csv') # For simulation "replay"

# EXACT COLUMN ORDER FROM YOUR DATASET (Critical for correct inference)
COLUMNS=['Destination Port', 'Flow Duration', 'Total Fwd Packets','Total Backward Packets', 'Total Length of Fwd Packets','Total Length of Bwd Packets', 'Fwd Packet Length Max','Fwd Packet Length Min', 'Fwd Packet Length Mean','Fwd Packet Length Std', 'Bwd Packet Length Max','Bwd Packet Length Min', 'Bwd Packet Length Mean','Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s','Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min','Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max','Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std','Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags','Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length','Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s','Min Packet Length', 'Max Packet Length', 'Packet Length Mean','Packet Length Std', 'Packet Length Variance', 'FIN Flag Count','SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count','URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio','Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size','Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes','Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward','Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward','Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean','Idle Std', 'Idle Max', 'Idle Min']

class RouterSystem:
    def __init__(self):
        print(f"[{datetime.now()}] 🟢 BOOTING ROUTER OS...")
        self.process = psutil.Process(os.getpid())
        
        # Load AI Brain
        print(f"[{datetime.now()}] 🧠 Loading AI Model & Scaler...")
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
        except FileNotFoundError:
            print(f"❌ ERROR: Artifacts not found at {MODEL_PATH}")
            sys.exit(1)
            
        print(f"[{datetime.now()}] ✅ System Ready. Listening on Virtual Interface.")

    def monitor_resources(self):
        """Returns RAM usage (MB) and CPU %"""
        mem = self.process.memory_info().rss / 1024 / 1024
        cpu = self.process.cpu_percent()
        return mem, cpu

    def verify_packet_flags(self, raw_features):
        """Debug function to verify we aren't seeing garbage flags"""
        # Create a series for easy lookup
        data = pd.Series(raw_features, index=COLUMNS)
        
        flags = []
        if data['SYN Flag Count'] > 0: flags.append("SYN")
        if data['FIN Flag Count'] > 0: flags.append("FIN")
        if data['ACK Flag Count'] > 0: flags.append("ACK")
        if data['PSH Flag Count'] > 0: flags.append("PSH")
        
        return flags, data['Flow Duration']

    def process_traffic(self, flow_features_raw, flow_id):
        """
        Simulates the processing of a completed flow.
        """
        # 1. Resource Check Before Processing
        mem_start, _ = self.monitor_resources()
        
        # 2. Preprocessing (Scaling)
        # Note: We simulate the transform time which happens on the router
        start_time = time.time()
        features_scaled = self.scaler.transform(flow_features_raw.reshape(1, -1))
        
        # 3. Inference
        prob = self.model.predict_proba(features_scaled)[0][1]
        prediction = "⛔ MALICIOUS" if prob > 0.5 else "✅ BENIGN"
        
        latency_ms = (time.time() - start_time) * 1000
        
        # 4. Deep Inspection (Verification)
        active_flags, duration = self.verify_packet_flags(flow_features_raw)
        
        # 5. Logging (Simulating Syslog)
        print("-" * 60)
        print(f"📦 FLOW ID: {flow_id} | Duration: {duration:.2f}ms")
        print(f"🚩 Active Flags: {active_flags}")
        print(f"🤖 AI Verdict: {prediction} (Confidence: {prob:.4f})")
        print(f"⚡ Latency: {latency_ms:.4f} ms | 💾 RAM: {mem_start:.2f} MB")
        
        if prediction == "⛔ MALICIOUS":
            print("🚨 ACTION: FIREWALL RULE UPDATED -> DROP PACKET")

def simulation_loop():
    router = RouterSystem()
    
    print(f"[{datetime.now()}] 📡 Connecting to Traffic Stream (Test Dataset)...")
    
    # Load Test Data for Simulation (Simulating incoming flows)
    # We load a small chunk to respect memory
    try:
        df = pd.read_csv(DATA_PATH, nrows=1000)
    except FileNotFoundError:
        print("❌ Data not found. Ensure 'cleaned_data.csv' is in outputs.")
        return

    # Clean data to match training shape
    # Assuming 'Label' is the last column to drop
    if 'Label' in df.columns:
        df_clean = df.drop(columns=['Label'])
    else:
        df_clean = df
        
    # Ensure only 79 numeric columns are passed
    # (Filter using the exact COLUMNS list)
    try:
        df_clean = df_clean[COLUMNS]
    except KeyError as e:
        print(f"❌ Column Mismatch: {e}")
        return

    X_test_stream = df_clean.values
    
    print(f"[{datetime.now()}] 🌊 Traffic Stream Established. Processing packets...")
    
    # SIMULATION LOOP
    # We pick random flows to simulate non-stop traffic
    try:
        while True:
            # Pick a random flow from our "Buffer"
            idx = np.random.randint(0, len(X_test_stream))
            flow_data = X_test_stream[idx]
            
            # Send to Router
            router.process_traffic(flow_data, flow_id=f"FL-{int(time.time())}-{idx}")
            
            # Simulate real-world gaps (routers aren't always 100% load)
            time.sleep(np.random.uniform(0.1, 1.0))
            
    except KeyboardInterrupt:
        print("\n🛑 SHUTTING DOWN ROUTER.")

if __name__ == "__main__":
    simulation_loop()