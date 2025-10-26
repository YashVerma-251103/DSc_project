"""
compare_dirs.py

Usage:
    python compare_dirs.py

What it does:
 - Compares matching CSV filenames in two directories (left_dir and right_dir)
 - Produces compare_reports/<filename>_report.txt with:
     - file sizes
     - sha256 checksums
     - row counts (streams CSV)
     - columns (list)
     - top label-value counts
     - first & last 3 rows (preview)
 - Produces a summary CSV: comparison_report.csv
 - If a file exists only in one dir, it's listed as such.

Edit left_dir and right_dir to point to your MachineLearningCVE and TrafficLabelling folders.
"""
import os, csv, hashlib, sys, json
from collections import Counter

# --- EDIT THESE PATHS if needed ---
left_dir = "../data/institute_files/MachineLearningCVE"
right_dir = "../data/institute_files/TrafficLabelling"
out_dir = "../compare_reports"
os.makedirs(out_dir, exist_ok=True)

def sha256_of_file(path, block_size=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            h.update(block)
    return h.hexdigest()

def csv_row_count_and_columns(path, encoding='utf-8', chunksize=100000):
    # Streams the file to count rows and capture header + first/last rows
    header = None
    first_rows = []
    last_rows = []
    row_count = 0
    cols = []
    try:
        with open(path, 'r', encoding=encoding, errors='replace') as f:
            reader = csv.reader(f)
            for row in reader:
                if header is None:
                    header = row
                    cols = header
                    continue
                row_count += 1
                if len(first_rows) < 3:
                    first_rows.append(row)
                last_rows.append(row)
                if len(last_rows) > 3:
                    last_rows.pop(0)
    except Exception as e:
        # Fallback: try to count lines quickly (binary)
        with open(path, 'rb') as f:
            row_count = sum(1 for _ in f) - 1
        header = []
    return int(row_count), cols, first_rows, last_rows

def top_label_counts(path, label_candidates=None, encoding='utf-8'):
    # Attempt to detect a label-like column (Label, label, Label_, etc.)
    # Return Counter for top values
    label_candidates = label_candidates or ['Label','label','Class','class','Attack','Flow ID','Label_']
    try:
        with open(path, 'r', encoding=encoding, errors='replace') as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return {}
            # find first candidate that is in fieldnames
            label_col = None
            for c in label_candidates:
                if c in reader.fieldnames:
                    label_col = c
                    break
            if label_col is None:
                # try heuristic: any fieldname with 'label' or 'class' in name
                for c in reader.fieldnames:
                    if 'label' in c.lower() or 'class' in c.lower() or 'attack' in c.lower():
                        label_col = c
                        break
            if label_col is None:
                return {}
            counter = Counter()
            # stream up to 20000 rows for counts (fast)
            for i, row in enumerate(reader):
                if row.get(label_col) is not None:
                    counter[row.get(label_col)] += 1
                if i >= 20000:
                    break
            return {'label_col': label_col, 'top_counts': counter.most_common(20)}
    except Exception as e:
        return {}

# get file lists
left_files = {f for f in os.listdir(left_dir) if f.lower().endswith('.csv')}
right_files = {f for f in os.listdir(right_dir) if f.lower().endswith('.csv')}
all_files = sorted(left_files.union(right_files))

summary_rows = []
for fname in all_files:
    left_path = os.path.join(left_dir, fname)
    right_path = os.path.join(right_dir, fname)
    row = {'file': fname}
    # existence
    row['left_exists'] = os.path.exists(left_path)
    row['right_exists'] = os.path.exists(right_path)

    # left file stats
    if row['left_exists']:
        try:
            row['left_size_bytes'] = os.path.getsize(left_path)
            row['left_sha256'] = sha256_of_file(left_path)
            left_count, left_cols, left_first, left_last = csv_row_count_and_columns(left_path)
            row['left_rowcount'] = left_count
            row['left_num_columns'] = len(left_cols)
            row['left_columns'] = json.dumps(left_cols, ensure_ascii=False)
            row['left_first_rows'] = json.dumps(left_first, ensure_ascii=False)
            row['left_last_rows'] = json.dumps(left_last, ensure_ascii=False)
            left_label_info = top_label_counts(left_path)
            row['left_label_col'] = left_label_info.get('label_col','')
            row['left_label_counts'] = json.dumps(left_label_info.get('top_counts',[]), ensure_ascii=False)
        except Exception as e:
            row['left_error'] = str(e)

    # right file stats
    if row['right_exists']:
        try:
            row['right_size_bytes'] = os.path.getsize(right_path)
            row['right_sha256'] = sha256_of_file(right_path)
            right_count, right_cols, right_first, right_last = csv_row_count_and_columns(right_path)
            row['right_rowcount'] = right_count
            row['right_num_columns'] = len(right_cols)
            row['right_columns'] = json.dumps(right_cols, ensure_ascii=False)
            row['right_first_rows'] = json.dumps(right_first, ensure_ascii=False)
            row['right_last_rows'] = json.dumps(right_last, ensure_ascii=False)
            right_label_info = top_label_counts(right_path)
            row['right_label_col'] = right_label_info.get('label_col','')
            row['right_label_counts'] = json.dumps(right_label_info.get('top_counts',[]), ensure_ascii=False)
        except Exception as e:
            row['right_error'] = str(e)

    # quick equality checks
    row['same_size'] = (row.get('left_size_bytes') == row.get('right_size_bytes')) if (row.get('left_size_bytes') and row.get('right_size_bytes')) else False
    row['same_sha256'] = (row.get('left_sha256') == row.get('right_sha256')) if (row.get('left_sha256') and row.get('right_sha256')) else False
    row['same_rowcount'] = (row.get('left_rowcount') == row.get('right_rowcount')) if ('left_rowcount' in row and 'right_rowcount' in row) else False
    # columns equality (string compare)
    row['same_num_columns'] = (row.get('left_num_columns') == row.get('right_num_columns')) if ('left_num_columns' in row and 'right_num_columns' in row) else False
    row['columns_match'] = (row.get('left_columns') == row.get('right_columns')) if ('left_columns' in row and 'right_columns' in row) else False

    summary_rows.append(row)

    # write per-file detailed report
    rpt_path = os.path.join(out_dir, fname.replace('.csv','') + "_report.txt")
    with open(rpt_path, 'w', encoding='utf-8') as rpt:
        rpt.write("Report for: {}\n\n".format(fname))
        rpt.write("Left exists: {}\nRight exists: {}\n\n".format(row['left_exists'], row['right_exists']))
        if row.get('left_exists'):
            rpt.write("LEFT\n")
            rpt.write(" size (bytes): {}\n".format(row.get('left_size_bytes')))
            rpt.write(" sha256: {}\n".format(row.get('left_sha256')))
            rpt.write(" rows: {}\n".format(row.get('left_rowcount')))
            rpt.write(" num columns: {}\n".format(row.get('left_num_columns')))
            rpt.write(" columns: {}\n".format(row.get('left_columns')))
            rpt.write(" label col: {}\n".format(row.get('left_label_col')))
            rpt.write(" top label counts (sample): {}\n".format(row.get('left_label_counts')))
            rpt.write(" first rows: {}\n".format(row.get('left_first_rows')))
            rpt.write(" last rows: {}\n".format(row.get('left_last_rows')))
            rpt.write("\n")
        if row.get('right_exists'):
            rpt.write("RIGHT\n")
            rpt.write(" size (bytes): {}\n".format(row.get('right_size_bytes')))
            rpt.write(" sha256: {}\n".format(row.get('right_sha256')))
            rpt.write(" rows: {}\n".format(row.get('right_rowcount')))
            rpt.write(" num columns: {}\n".format(row.get('right_num_columns')))
            rpt.write(" columns: {}\n".format(row.get('right_columns')))
            rpt.write(" label col: {}\n".format(row.get('right_label_col')))
            rpt.write(" top label counts (sample): {}\n".format(row.get('right_label_counts')))
            rpt.write(" first rows: {}\n".format(row.get('right_first_rows')))
            rpt.write(" last rows: {}\n".format(row.get('right_last_rows')))
            rpt.write("\n")
        rpt.write("Comparison summary:\n")
        rpt.write(" same_size: {}\n".format(row.get('same_size')))
        rpt.write(" same_sha256: {}\n".format(row.get('same_sha256')))
        rpt.write(" same_rowcount: {}\n".format(row.get('same_rowcount')))
        rpt.write(" same_num_columns: {}\n".format(row.get('same_num_columns')))
        rpt.write(" columns_match: {}\n".format(row.get('columns_match')))

# write summary CSV
import pandas as pd
pd.DataFrame(summary_rows).to_csv(os.path.join(out_dir, "comparison_report.csv"), index=False)
print("Comparison finished. Summary saved to:", os.path.join(out_dir, "comparison_report.csv"))
print("Per-file reports in:", out_dir)
