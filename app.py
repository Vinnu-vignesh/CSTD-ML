import pandas as pd
import numpy as np
import joblib
import os
import datetime

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from io import BytesIO

# --- Configuration ---
app = Flask(__name__)
CORS(app)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FOLDER = os.path.join(BASE_DIR, "classified_outputs")
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

MODEL_PATH = 'Random_forest_traffic_classifier.pkl'

# Mapping the numerical predictions back to labels.
PREDICTION_MAP = {
    0: 'Benign',
    1: 'Malicious'
}

try:
    MODEL = joblib.load(MODEL_PATH)
    print("ML Model loaded successfully.")
except Exception as e:
    MODEL = None
    print(f"ERROR loading model: {e}")


# ---------- NAP VALIDATION LOGIC (NEW) ----------

def is_valid_packet(row: pd.Series) -> bool:
    """
    Returns True if row looks like a valid packet/flow.
    Returns False if values indicate NAP (Not A Packet).
    """

    def g(col):
        return row[col] if col in row.index else np.nan

    # 1) Flow Duration must be >= 0
    fd = g("Flow Duration")
    if pd.isna(fd) or fd < 0:
        return False

    # 2) Packet size sanity
    size_fields = [
        "Fwd Pkt Len Max", "Fwd Pkt Len Mean",
        "Bwd Pkt Len Max", "Bwd Pkt Len Mean",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        "Pkt Size Avg"
    ]

    for col in size_fields:
        if col not in row.index:
            continue
        val = g(col)
        if pd.isna(val):
            continue
        if val < 0:
            return False
        # individual packet size shouldn't be insanely high
        if ("Pkt Len" in col or "Pkt Size" in col) and val > 2000:
            return False

    # mean must not exceed max (when both present)
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

    # zero packets but non-zero total length
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

    # infinite rates typically indicate division by zero (0 duration)
    if np.isinf(fpkts_s) or np.isinf(fbytes_s):
        return False

    # 5) IAT checks (basic)
    iat_fields = [
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Mean", "Fwd IAT Std",
        "Bwd IAT Mean"
    ]
    for col in iat_fields:
        if col not in row.index:
            continue
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

    # Looks valid
    return True


# --- Flask Routes ---

@app.route('/', methods=['GET'])
def home():
    """A simple status check for the backend."""
    return "Cyber Threat Prediction Backend Backend is Running!"


@app.route('/api/predict', methods=['POST'])
def predict_csv():
    if MODEL is None:
        return jsonify({'error': 'Prediction model is not loaded.'}), 503

    if 'file' not in request.files or not request.files['file'].filename:
        return jsonify({'error': 'No file part or selected file in the request.'}), 400

    file = request.files['file']

    try:
        file_stream = file.stream
        file_stream.seek(0)
        df = pd.read_csv(file_stream)

        # Keep original data for final output
        df.columns = df.columns.str.strip()
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_original = df.copy()

        # ---- NEW: NAP detection first ----
        valid_mask = df_original.apply(is_valid_packet, axis=1)
        nap_mask = ~valid_mask

        # Prepare output dataframe with all original rows
        df_output = df_original.copy()
        df_output['Predicted_Label'] = None

        # Label NAP rows
        df_output.loc[nap_mask, 'Predicted_Label'] = 'NAP'

        # ---- Prepare data for ML model only on valid rows ----
        df_for_model = df_original.loc[valid_mask].copy()

        # Drop non-numeric (like before)
        object_cols = df_for_model.select_dtypes(include=['object']).columns
        if len(object_cols) > 0:
            df_for_model.drop(columns=object_cols, inplace=True)

        # Drop rows with NaN for the model
        df_for_model.dropna(inplace=True)

        if not df_for_model.empty:
            # Predict on valid + clean rows
            predictions_encoded = MODEL.predict(df_for_model)

            y_predictions_labels = pd.Series(
                predictions_encoded,
                index=df_for_model.index
            ).map(PREDICTION_MAP)

            # Fill predictions back into df_output
            df_output.loc[df_for_model.index, 'Predicted_Label'] = y_predictions_labels

        # Any remaining rows without label (e.g., valid but not enough data for model)
        df_output['Predicted_Label'].fillna('NAP', inplace=True)

        # ---------- Save classified CSV to disk ----------
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        out_filename = f"classified_{timestamp}.csv"
        out_path = os.path.join(OUTPUT_FOLDER, out_filename)
        df_output.to_csv(out_path, index=False)
        # -------------------------------------------------

        # Prepare for download
        buffer = BytesIO()
        df_output.to_csv(buffer, index=False)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype='text/csv',
            as_attachment=True,
            download_name=out_filename
        )

    except KeyError as e:
        return jsonify({'error': f'Missing expected column in CSV: {e}. Check your input data format.'}), 400
    except Exception as e:
        print(f"Prediction Error: {e}")
        return jsonify({'error': f'An error occurred during prediction: {str(e)}'}), 500


@app.route('/api/files', methods=['GET'])
def list_classified_files():
    """
    Returns list of classified CSV filenames stored on server.
    Basic, no auth check – frontend will show this only to admin.
    """
    try:
        files = []
        for name in os.listdir(OUTPUT_FOLDER):
            if name.endswith('.csv'):
                files.append(name)

        # latest first
        files.sort(reverse=True)

        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/files/<path:filename>', methods=['GET'])
def download_classified_file(filename):
    """
    Download a specific classified CSV by filename.
    """
    try:
        return send_from_directory(
            OUTPUT_FOLDER,
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
