# This script proves that your saved model actually works "Inference-only" without the training data.

import joblib, time
import numpy as np, pandas as pd

# SIMULATED ROUTER ENVIRONMENT
MODEL_PATH = "../outputs/endsem/router_model_coreset_5pct.joblib"
SCALER_PATH = "../outputs/endsem/router_scaler.joblib"
# COLUMNS=['Destination Port', 'Flow Duration', 'Total Fwd Packets','Total Backward Packets', 'Total Length of Fwd Packets','Total Length of Bwd Packets', 'Fwd Packet Length Max','Fwd Packet Length Min', 'Fwd Packet Length Mean','Fwd Packet Length Std', 'Bwd Packet Length Max','Bwd Packet Length Min', 'Bwd Packet Length Mean','Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s','Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min','Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max','Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std','Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags','Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length','Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s','Min Packet Length', 'Max Packet Length', 'Packet Length Mean','Packet Length Std', 'Packet Length Variance', 'FIN Flag Count','SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count','URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio','Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size','Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes','Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward','Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward','Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean','Idle Std', 'Idle Max', 'Idle Min', 'Label', 'Label_Binary']


def load_router_brain():
    print("BOOTING UP ROUTER AI...")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("SYSTEM READY.\nROUTER AI ONLINE.")
    return model, scaler

def inspect_packet(packet_features, model, scaler):
    #* 1. Scale -- using saved stats
    #? Reshaping because it's a single sample.
    scaled_packet = scaler.transform(packet_features.reshape(1, -1))

    #* 2. Predict
    start = time.time()
    prob = model.predict_proba(scaled_packet)[0][1]  # Probability of being malicious.
    latency = (time.time() - start) * 1000  # in milliseconds
    decision = "BLOCK" if prob >= 0.5 else "ALLOW"
    return decision, prob, latency

if __name__ == "__main__":
    # Load the router brain (model + scaler)
    model, scaler = load_router_brain()

    # Simulated incoming packets (random data for demonstration)
    np.random.seed(42)
    for i in range(5):
        packet = np.random.rand(78)  # 78 features as in the original dataset
        decision, prob, latency = inspect_packet(packet, model, scaler)
        print(f"Packet {i+1}: Decision={decision}, Malicious_Prob={prob:.4f}, Latency={latency:.2f}ms")


