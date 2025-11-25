# CSTD-ML
Its all about Threat Detection Using Machine Learning, as a batch analysis of offline csv network packet data.

# WebBased-CSTD
Its all about Threat Detection Using Machine Learning, as a batch analysis of offline csv network packet data.

Offline Network Threat Analysis Platform using Machine Learning

🛡️ Project Overview

This project develops a Web-based Cyber Security Threat Detection Platform (CSTD) that leverages Machine Learning for offline/batch analysis of network traffic logs. The goal is to provide a fast, accurate, and scalable solution for security analysts to process historical or captured network data and immediately flag malicious activity (e.g., Botnets).

Core Objective: Batch Threat Classification

The primary functionality of this application is Batch Prediction. The user uploads a CSV file containing network flow features. The system utilizes a pre-trained Random Forest Classifier to analyze the data, classify each packet as Benign or Bot, and immediately return a downloadable, classified CSV file.

🏗️ System Architecture and Data Flow

The CSTD Platform employs a lightweight, decoupled architecture for rapid development and high performance.

Presentation Tier (Frontend): React.js provides an aesthetic, dark-themed User Interface (UI) for file upload and status monitoring.

Application Tier (Backend): Python Flask serves as the API layer, managing file handling, orchestrating the prediction process, and handling CORS to enable communication with the React frontend.

Prediction Tier (ML Logic): The pre-trained Scikit-learn (Random Forest) model is loaded via joblib to perform high-speed classification on the preprocessed data.

Data Flow Summary:

User uploads a CSV via the React UI.

React uses Axios to send the file as a POST request to the Flask API endpoint (/api/predict).

The Flask server runs the ML prediction and preprocessing pipeline.

Flask returns the classified data as a new CSV file.

🧠 Machine Learning Model Preparation

The core of the CSTD project is the predictive model, which requires specific preparation steps to ensure reliable classification.

1. Training and Model Selection

Model: Random Forest Classifier (selected for high accuracy and robustness in anomaly detection).

Dataset: Based on network flow features (e.g., KDD, CICFlowMeter data).

Output: The trained model is saved using the joblib library as random_forest_traffic_classifier.pkl.

2. Mandatory Preprocessing Pipeline

The live application must replicate the exact preprocessing steps used during training. This is handled by the Flask backend (app.py):

Column Sanitization: Strip leading/trailing whitespaces from column names.

Anomaly Handling: Convert infinite (inf, -inf) values in the input data to NaN.

Missing Data Removal: Drop any rows containing NaN values to ensure valid numerical input.

Feature Selection: Drop all non-numeric, categorical features (e.g., protocol_type, service) that were not encoded during training.

The model only receives the cleaned, processed, purely numerical feature set.

🚀 Local Setup and Deployment

Prerequisites

Python 3.x

Node.js and npm/yarn (for React)

1. Backend Setup (Flask & ML)

Clone the Repository:

git clone [YOUR-REPO-URL]
cd [backend-folder]


Virtual Environment:

python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate


Install Dependencies:

pip install Flask pandas scikit-learn joblib flask-cors


Model File: Ensure your trained model is named random_forest_traffic_classifier.pkl and is in the root backend directory.

Run Server:

python app.py
# Server should start on [http://127.0.0.1:5000/](http://127.0.0.1:5000/)


2. Frontend Setup (React)

Navigate to Frontend:

cd [frontend-folder/react-project]


Install Dependencies:

npm install
npm install axios  # Required for API communication


Run Frontend:

npm start
# Application should open on http://localhost:3000/
