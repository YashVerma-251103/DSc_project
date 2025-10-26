# 🧠 **README — Data Science Project (Mid-Semester Phase)**
### *A Data Science Approach to Network Intrusion Detection using CIC-IDS-2017 Dataset*

---

## 📘 **Overview**

This repository contains all files, notebooks, and outputs for the **mid-semester phase** of the Data Science Project.  
The objective of this phase is to **understand, clean, explore, and statistically analyze** the *CIC-IDS-2017* dataset — a benchmark dataset for network intrusion detection.

No machine learning models are trained at this stage.  
The focus is entirely on **data preparation, exploratory analysis, and inferential statistics**.

---

## 🎯 **Project Objective**

> To analyze the CIC-IDS-2017 dataset to uncover statistically significant behavioral differences between benign and attack network traffic, preparing the data for later machine learning-based intrusion detection.

**Core Goals:**
1. Load, merge, and verify the dataset structure.  
2. Clean and preprocess the data for consistency and accuracy.  
3. Perform visual and statistical exploratory analysis (EDA).  
4. Conduct hypothesis testing to confirm significant feature differences.  
5. Derive interpretable insights for future ML modeling.

---

## 🗂️ **Repository Structure**

```
├── data/
│   ├── MachineLearningCVE/         # Raw CSV files (Monday–Friday network captures)
│   └── TrafficLabelling/           # Alternate labeled version (for comparison)
│
├── notebooks/
│   ├── Data_understanding.ipynb    # Dataset loading, info summary, feature inventory
│   ├── dp2.ipynb                   # Data cleaning & preprocessing
│   ├── ea2.ipynb                   # Exploratory Data Analysis (EDA)
│   ├── stat2.ipynb                 # Statistical inference (hypothesis testing)
│   └── (optional) 04_Result_Interpretation.ipynb  # Automated result summarization
│
├── outputs/
│   ├── descriptive_summary.csv
│   ├── test_results.csv
│   ├── feature_attack_correlation.csv
│   ├── class_balance.csv
│   ├── data_understanding_summary.csv
│   ├── feature_summary_simple.csv
│   ├── correlation_heatmap_simple.png
│   ├── class_distribution_simple.png
│   ├── distribution_*.png
│   ├── boxplot_*.png
│   ├── top_attack_types_simple.png
│   └── (more plots, generated automatically)
│
│
├── README.md                       # (This file)
└── requirements.txt                # Python libraries used
```

---

## 🧰 **Dependencies**

This project was developed using **Python 3.10+** in a **Jupyter Notebook environment**.

**Install required libraries:**
```bash
pip install pandas numpy matplotlib seaborn scipy
```

**Optional (for large CSV handling):**
```bash
pip install polars pyarrow
```

---

## ⚙️ **Workflow**

| Step | Notebook | Description | Key Output |
|------|-----------|--------------|-------------|
| 1️⃣ | `Data_understanding.ipynb` | Load and inspect CSV files, verify column consistency, generate data summary | `data_understanding_summary.csv`, `columns_list.csv` |
| 2️⃣ | `dp2.ipynb` | Handle missing/infinite values, duplicates, encoding; clean & save merged dataset | `cleaned_data.csv`, `descriptive_summary.csv`, `class_balance.csv` |
| 3️⃣ | `ea2.ipynb` | Visualize distributions, correlations, attack types | EDA plots (`distribution_*.png`, `boxplot_*.png`, `correlation_heatmap_simple.png`) |
| 4️⃣ | `stat2.ipynb` | Conduct hypothesis testing using non-parametric tests | `test_results.csv` |
| (optional) | `04_Result_Interpretation.ipynb` | Summarize all findings automatically | `result_interpretation.txt`, `significant_features.csv` |

---

## 🔬 **Statistical Hypotheses Tested**

| ID | Feature | Test Used | H₀ (Null Hypothesis) | H₁ (Alternative Hypothesis) | p-value | Result |
|----|----------|------------|-----------------------|-----------------------------|----------|---------|
| **H₁** | Flow Duration | Mann–Whitney U | Flow Duration is equal across Benign & Attack flows | Flow Duration differs across Benign & Attack flows | < 0.001 | Reject H₀ ✅ |
| **H₂** | Total Fwd Packets | Mann–Whitney U | No difference in packet count across attack types | Packet count differs across attack types | < 0.001 | Reject H₀ ✅ |
| **H₃** | Flow Bytes/s | Kruskal–Wallis | No difference in throughput variance | Throughput variance differs between traffic classes | < 0.001 | Reject H₀ ✅ |
| **H₄** | Protocol vs Attack | Chi-Square | Protocol is independent of attack occurrence | Protocol influences attack likelihood | 0.02 | Reject H₀ ✅ |
| **H₅** | Idle Mean/Max | Mann–Whitney U | Idle intervals are similar in both classes | Idle intervals differ between Benign and Attack flows | < 0.001 | Reject H₀ ✅ |

✅ All tests show **p < 0.05**, confirming statistically significant behavioral differences.

---

## 📊 **Key Insights**

1. Attack flows are **longer, more bursty, and more data-intensive** than benign flows.  
2. Features like **Bwd Packet Length Std**, **Fwd IAT Std**, **Idle Mean**, and **Idle Max** have strong correlation with attack presence.  
3. The dataset is **imbalanced** (83% Benign) — future ML models must handle class imbalance.  
4. Minor **CICFlowMeter artifacts** observed (120-second timeout leading to benign reversal).  
5. Dataset is **clean, validated, and modeling-ready**.

---

## 🧩 **Reproducibility & Provenance**

Each output file can be traced back to its generating notebook:

| Output | Produced By | Used In |
|---------|--------------|---------|
| `descriptive_summary.csv` | dp2.ipynb | Report → Data Preparation section |
| `test_results.csv` | stat2.ipynb | Report → Statistical Inference section |
| `feature_attack_correlation.csv` | ea2.ipynb | Report → EDA & Correlation section |
| `class_distribution_simple.png` | ea2.ipynb | Report → EDA section |
| `correlation_heatmap_simple.png` | ea2.ipynb | Report → EDA section |
| `boxplot_*.png` | ea2.ipynb | Report → Outlier Analysis section |
| `result_interpretation.txt` | optional notebook | Report → Insights section |

---

## 🚀 **How to Run the Project**

**Step 1:** Clone or copy the repository.  
**Step 2:** Place raw CSVs inside `data/MachineLearningCVE/`.  
**Step 3:** Open Jupyter Notebook and execute sequentially:
```bash
1. notebooks/Data_understanding.ipynb
2. notebooks/dp2.ipynb
3. notebooks/ea2.ipynb
4. notebooks/stat2.ipynb
```
**Step 4:** View generated outputs in the `outputs/` directory.  
**Step 5:** Use results and plots to compile your report and presentation.

---

## 📄 **What’s Next (End-Semester Phase)**

The next phase will involve:
- **Machine Learning Modeling:** Logistic Regression, Decision Tree, Random Forest, XGBoost.  
- **Model Evaluation:** Accuracy, Precision, Recall, F1-score, ROC Curve.  
- **Feature Selection:** Based on correlation & statistical significance.  
- **Class Imbalance Handling:** SMOTE or class-weight adjustment.  

---

## 👩‍💻 **Contributors**

| Name | Role | Area |
|------|------|------|
| *[Your Name]* | Data Preparation & Cleaning | Data pipeline, preprocessing |
| *[Teammate Name]* | EDA & Visualization | Feature distribution, correlation |
| *[Teammate Name]* | Statistical Inference | Hypothesis testing, interpretation |
| *Mentor / Faculty* | Project Guidance | Conceptual supervision |

---

## 📚 **References**

1. Sharafaldin, I., Lashkari, A.H., & Ghorbani, A.A. (2018).  
   *Toward Generating a New Intrusion Detection Dataset (CIC-IDS2017)*.  
   International Conference on Information Systems Security and Privacy (ICISSP).  
2. Canadian Institute for Cybersecurity (CIC) — Dataset repository.  
3. Python libraries: *Pandas*, *NumPy*, *Matplotlib*, *Seaborn*, *SciPy*.

---

## ✅ **Status**
✔️ **Mid-Semester Phase Completed**  
⚙️ **End-Semester (Modeling Phase) — In Progress**
