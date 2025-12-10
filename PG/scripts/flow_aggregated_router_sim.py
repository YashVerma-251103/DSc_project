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
DATA_PATH = os.path.join(BASE_DIR,'../outputs/endsem/router_traffic.csv') # For simulation "replay"

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
        return mem

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

    def process_traffic(self, flow_features_raw, flow_id,true_label_str):
        """
        Simulates the processing of a completed flow.
        """
        # 1. Resource Check Before Processing
        mem_start = self.monitor_resources()
        
        # 2. Preprocessing (Scaling)
        # Note: We simulate the transform time which happens on the router
        start_time = time.time()
        features_scaled = self.scaler.transform(flow_features_raw.reshape(1, -1))
        
        # 3. Inference
        prob = self.model.predict_proba(features_scaled)[0][1]
        prediction_int = 1 if prob > 0.5 else 0
        prediction = "⛔ MALICIOUS" if prob > 0.5 else "✅ BENIGN"
        
        latency_ms = (time.time() - start_time) * 1000
        
        # 3. VERIFICATION (The "Truth" Check)
        # Convert String Label (e.g. "DoS Hulk") to Binary (Malicious/Benign)
        is_actually_malicious = (true_label_str != "BENIGN")
        actual_str = "MALICIOUS" if is_actually_malicious else "BENIGN"
        
        # Did we get it right?
        is_correct = (prediction_int == 1 and is_actually_malicious) or \
                     (prediction_int == 0 and not is_actually_malicious)
        
        status_icon = "🎯 CORRECT" if is_correct else "⚠️ MISS/FALSE ALARM"


        # 4. Deep Inspection (Verification)
        active_flags, duration = self.verify_packet_flags(flow_features_raw)
        
        # 5. Logging (Simulating Syslog)
        print("-" * 60)
        print(f"📦 FLOW ID: {flow_id} | Duration: {duration:.2f}ms")
        print(f"🚩 Active Flags: {active_flags}")
        print(f"🤖 AI Verdict: {prediction} (Attack Probability: {prob:.4f})")
        print(f"📝 True Label: {true_label_str} ({actual_str})")
        print(f"⚡ Latency: {latency_ms:.4f} ms | 💾 RAM: {mem_start:.2f} MB")
        
        if prediction_int == 1:
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

    try:
        # Read dataset (containing both Features AND Labels)
        df = pd.read_csv(DATA_PATH)
        
        # Separate Features (X) and Labels (y)
        # We assume 'Label' is the column name for the ground truth
        if 'Label' not in df.columns:
            print("❌ Error: 'Label' column missing in router_traffic.csv")
            return

        # Extract features ensuring correct column order
        X_stream = df[COLUMNS].values
        y_stream = df['Label'].values
        
    except Exception as e:
        print(f"❌ Data Load Error: {e}")
        return

    print(f"[{datetime.now()}] 🌊 Processing {len(X_stream)} flows...")
    
    try:
        while True:
            # Pick a random flow
            idx = np.random.randint(0, len(X_stream))
            
            flow_data = X_stream[idx]     # The features (numbers)
            true_label = y_stream[idx]    # The truth (string)
            
            # Send to Router with the Truth for verification
            router.process_traffic(
                flow_data, 
                flow_id=f"FL-{int(time.time())}-{idx}", 
                true_label_str=true_label
            )
            
            time.sleep(np.random.uniform(0.5, 2.0))
            
    except KeyboardInterrupt:
        print("\n🛑 SHUTTING DOWN ROUTER.")
    

if __name__ == "__main__":
    simulation_loop()