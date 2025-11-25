// src/App.js

import React from 'react';
// 1. Import your new component
import PredictionPortal from './predictionPortel';
import './App.css'; // Keep the standard CSS import

function App() {
  return (
    // The main container for your entire application
    <div className="App">

      {/* 2. This is where the file upload and prediction logic is rendered */}
      <PredictionPortal />

      <footer style={{ marginTop: '50px', fontSize: '0.8em', color: '#666', textAlign: 'center' }}>
        <p>Project Backend running on Flask at 127.0.0.1:5000</p>
      </footer>
    </div>
  );
}

export default App;