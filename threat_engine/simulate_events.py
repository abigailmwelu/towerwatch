"""
Generates synthetic event features for AI model training.

This module provides functions to create realistic network traffic data for testing and
training the TowerWatch threat detection system. It generates both normal and
anomalous event patterns with realistic network traffic features.
"""

import numpy as np
from typing import List, Dict, Tuple, Union
import random
from datetime import datetime, timedelta
import string


def generate_normal_sample(n_samples: int = 1000, random_seed: int = 42) -> np.ndarray:
    """Generate synthetic normal network traffic data.
    
    Feature vector order:
    [failed_logins, successful_logins, bytes_sent, bytes_recv, destination_port, hour_of_day]
    
    Args:
        n_samples: Number of samples to generate
        random_seed: Random seed for reproducibility
        
    Returns:
        Numpy array of shape (n_samples, 6) with normal traffic features
    """
    np.random.seed(random_seed)
    random.seed(random_seed)
    
    # Common ports for normal traffic
    COMMON_PORTS = [80, 443, 22, 53, 123, 8080, 8443]
    
    # Generate realistic normal traffic patterns
    data = []
    
    for _ in range(n_samples):
        # Most sessions have 0 failed logins
        failed_logins = np.random.poisson(0.1)
        
        # Successful logins are more common during business hours
        hour = random.randint(0, 23)
        login_prob = 0.3 + 0.5 * np.exp(-0.5 * ((hour - 14) / 4) ** 2)  # Peak at 2 PM
        successful_logins = np.random.binomial(1, login_prob)
        
        # Bytes sent/received (log-normal distribution)
        bytes_sent = int(np.random.lognormal(8, 2))
        bytes_recv = int(np.random.lognormal(10, 2))
        
        # Destination port (weighted towards common ports)
        if random.random() < 0.9:  # 90% chance of common port
            port = random.choice(COMMON_PORTS)
        else:
            port = random.randint(1024, 65535)
        
        data.append([
            failed_logins,
            successful_logins,
            bytes_sent,
            bytes_recv,
            port,
            hour
        ])
    
    return np.array(data, dtype=np.float32)


def generate_outlier_sample(n_samples: int = 100, random_seed: int = 42) -> np.ndarray:
    """Generate synthetic anomalous network traffic data.
    
    Feature vector order:
    [failed_logins, successful_logins, bytes_sent, bytes_recv, destination_port, hour_of_day]
    
    Args:
        n_samples: Number of samples to generate
        random_seed: Random seed for reproducibility
        
    Returns:
        Numpy array of shape (n_samples, 6) with anomalous traffic features
    """
    np.random.seed(random_seed)
    random.seed(random_seed)
    
    # Suspicious ports often used in attacks
    SUSPICIOUS_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
        445, 587, 993, 995, 1433, 1521, 1723, 2049, 3306, 3389, 
        5432, 5900, 6000, 8000, 8080, 8443, 27017, 27018, 27019
    ]
    
    data = []
    
    for _ in range(n_samples):
        # Anomaly type: 0=brute force, 1=data exfiltration, 2=port scan, 3=odd hours
        anomaly_type = random.choice([0, 1, 2, 3])
        
        if anomaly_type == 0:  # Brute force attack
            failed_logins = np.random.poisson(20)  # Many failed logins
            successful_logins = 0
            bytes_sent = np.random.lognormal(6, 1)
            bytes_recv = np.random.lognormal(6, 1)
            port = random.choice([22, 23, 3389, 5900])  # Common brute force targets
            hour = random.randint(0, 23)  # Can happen any time
            
        elif anomaly_type == 1:  # Data exfiltration
            failed_logins = np.random.poisson(0.1)
            successful_logins = 1  # Attacker got in
            bytes_sent = np.random.lognormal(16, 2)  # Large data transfer out
            bytes_recv = np.random.lognormal(6, 1)
            port = random.choice([80, 443, 53, 123])  # Common exfiltration ports
            hour = random.choice([1, 2, 3, 4])  # Odd hours
            
        elif anomaly_type == 2:  # Port scan
            failed_logins = np.random.poisson(0.5)
            successful_logins = 0
            bytes_sent = np.random.lognormal(4, 1)  # Small packets
            bytes_recv = np.random.lognormal(4, 1)
            port = random.choice(SUSPICIOUS_PORTS)  # Random suspicious port
            hour = random.randint(0, 23)
            
        else:  # Odd hour activity
            failed_logins = np.random.poisson(0.5)
            successful_logins = np.random.binomial(1, 0.2)  # Some successful logins
            bytes_sent = np.random.lognormal(10, 2)
            bytes_recv = np.random.lognormal(10, 2)
            port = random.randint(1024, 65535)  # Random high port
            hour = random.choice([0, 1, 2, 3, 4, 22, 23])  # Late night/early morning
        
        data.append([
            failed_logins,
            successful_logins,
            bytes_sent,
            bytes_recv,
            port,
            hour
        ])
    
    return np.array(data, dtype=np.float32)


def generate_training_matrix(n_normals: int = 1000, 
                           n_outliers: int = 100,
                           random_seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Generate separate normal and outlier datasets for training.
    
    Args:
        n_normals: Number of normal samples to generate
        n_outliers: Number of outlier samples to generate
        random_seed: Random seed for reproducibility
        
    Returns:
        Tuple of (X_normal, X_outliers) where each is a numpy array
        with shape (n_samples, 6) containing the feature vectors
    """
    # Generate normal traffic
    X_normal = generate_normal_sample(n_normals, random_seed=random_seed)
    
    # Generate anomalous traffic
    X_outliers = generate_outlier_sample(n_outliers, random_seed=random_seed + 1)
    
    return X_normal, X_outliers
