"""
Train TowerWatch AI engine with simulated traffic.

This module provides functionality to train and manage the TowerWatch AI engine
using synthetic network traffic data. It handles model training, evaluation,
and persistence for different tenants.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from datetime import datetime

# Import from local modules
from .engine import TowerWatchEngine
from .simulate_events import generate_training_matrix

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MODELS_DIR = Path(__file__).parent / 'models'
MODELS_DIR.mkdir(exist_ok=True, parents=True)


def train_tenant(tenant_id: str = "global", 
                n_normals: int = 1000, 
                n_outliers: int = 30,
                random_state: int = 42) -> Dict[str, Any]:
    """Train TowerWatch AI engine with simulated traffic.
    
    Args:
        tenant_id: Unique identifier for the tenant (default: "global")
        n_normals: Number of normal traffic samples to generate
        n_outliers: Number of anomalous traffic samples to generate
        random_state: Random seed for reproducibility
        
    Returns:
        Dictionary containing training results and model metadata
    """
    logger.info(f"Starting training for tenant: {tenant_id}")
    
    # 1. Generate synthetic training data
    logger.info(f"Generating {n_normals} normal and {n_outliers} anomalous samples")
    X_normal, X_outliers = generate_training_matrix(
        n_normals=n_normals,
        n_outliers=n_outliers,
        random_seed=random_state
    )
    
    # Combine normal and outlier samples
    X = np.vstack([X_normal, X_outliers])
    
    # 2. Initialize TowerWatchEngine
    engine = TowerWatchEngine()
    
    # 3. Train the model
    logger.info("Training Isolation Forest model...")
    train_result = engine.train(
        X,
        persist=True,
        contamination=float(n_outliers) / (n_normals + n_outliers),
        random_state=random_state
    )
    
    # 4. Save model with tenant-specific path
    model_dir = MODELS_DIR / tenant_id
    model_dir.mkdir(exist_ok=True, parents=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    model_path = model_dir / f"model_{timestamp}.joblib"
    
    # Save model with metadata
    model_data = {
        'model': engine.model,
        'metadata': {
            'tenant_id': tenant_id,
            'trained_at': datetime.utcnow().isoformat(),
            'n_normal_samples': n_normals,
            'n_anomaly_samples': n_outliers,
            'feature_names': [
                'failed_logins',
                'successful_logins',
                'bytes_sent',
                'bytes_recv',
                'destination_port',
                'hour_of_day'
            ]
        },
        'training_params': {
            'random_state': random_state,
            'contamination': float(n_outliers) / (n_normals + n_outliers)
        }
    }
    
    joblib.dump(model_data, model_path)
    logger.info(f"Model saved to {model_path}")
    
    # Prepare results
    results = {
        'status': 'success',
        'tenant_id': tenant_id,
        'model_path': str(model_path),
        'n_normal_samples': n_normals,
        'n_anomaly_samples': n_outliers,
        'training_metrics': train_result.get('metrics', {})
    }
    
    return results


def load_model(tenant_id: str = "global") -> Dict[str, Any]:
    """Load a trained model for the specified tenant.
    
    Args:
        tenant_id: Unique identifier for the tenant (default: "global")
        
    Returns:
        Dictionary containing the model and metadata
    """
    model_dir = MODELS_DIR / tenant_id
    
    # Find the latest model
    model_files = sorted(model_dir.glob("model_*.joblib"), key=os.path.getmtime)
    if not model_files:
        raise FileNotFoundError(f"No model found for tenant: {tenant_id}")
    
    latest_model = model_files[-1]
    logger.info(f"Loading model: {latest_model}")
    
    return joblib.load(latest_model)


if __name__ == "__main__":
    train_tenant(tenant_id="global")
    print(f"Trained model for tenant global. Artifact should be in threat_engine/models/global/model_*.joblib")
