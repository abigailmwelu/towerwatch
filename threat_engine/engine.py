"""
TowerWatch Core AI Threat Engine — Handles detection, scoring, and rule checks

This module serves as the core component of the TowerWatch system, responsible for:
- Detecting potential security threats in AI model interactions
- Scoring the severity and confidence of detected threats
- Applying custom security rules and policies
- Managing the threat detection pipeline
- Hybrid rule-based and ML-powered threat detection
"""

from typing import Dict, Any, Optional, List, Union
import logging
import json
from pathlib import Path

class TowerWatchEngine:
    """Hybrid rule + ML detection engine for TowerWatch.
    
    Combines traditional rule-based detection with machine learning models
    for comprehensive threat detection in AI interactions.
    """
    
    def __init__(self, model_path: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        """Initialize the TowerWatch detection engine.
        
        Args:
            model_path: Path to a pre-trained model (optional)
            config: Configuration dictionary for the engine
        """
        self.model = None
        self.rules = []
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        if model_path:
            self.load_model(model_path)
    
    def detect(self, input_data: Union[str, Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """Detect potential threats in the input data.
        
        Args:
            input_data: Input text or structured data to analyze
            **kwargs: Additional detection parameters
            
        Returns:
            Dictionary containing detection results, scores, and metadata
        """
        results = {
            'threat_detected': False,
            'confidence': 0.0,
            'threat_type': None,
            'details': {}
        }
        
        try:
            # Apply rule-based detection
            rule_results = self._apply_rules(input_data)
            
            # Apply ML-based detection if model is loaded
            ml_results = {}
            if self.model:
                ml_results = self._apply_ml_detection(input_data)
            
            # Combine and analyze results
            results.update(self._analyze_results(rule_results, ml_results))
            
        except Exception as e:
            self.logger.error(f"Error during threat detection: {str(e)}", exc_info=True)
            results['error'] = str(e)
        
        return results
    
    def train(self, X, persist: bool = True, contamination: float = 0.1, **kwargs) -> Dict[str, Any]:
        """Train TowerWatch AI engine per tenant.
        
        Args:
            X: Training data matrix (n_samples, n_features)
            persist: Whether to save the trained model to disk
            contamination: Expected proportion of outliers in the data
            **kwargs: Additional parameters for the IsolationForest
            
        Returns:
            Dictionary containing training results and model metadata
        """
        from sklearn.ensemble import IsolationForest
        import numpy as np
        from pathlib import Path
        import joblib
        from datetime import datetime
        
        # Initialize model with tenant-specific contamination
        self.logger.info(f"Training IsolationForest with contamination={contamination}")
        model = IsolationForest(
            n_estimators=kwargs.get('n_estimators', 100),
            max_samples=kwargs.get('max_samples', 'auto'),
            contamination=contamination,
            max_features=kwargs.get('max_features', 1.0),
            bootstrap=kwargs.get('bootstrap', False),
            n_jobs=kwargs.get('n_jobs', -1),
            random_state=kwargs.get('random_state', 42),
            verbose=kwargs.get('verbose', 1)
        )
        
        # Convert input to numpy array if needed
        if not isinstance(X, np.ndarray):
            X = np.array(X)
        
        # Train the model
        model.fit(X)
        
        # Calculate training metrics
        scores = model.score_samples(X)
        threshold = np.percentile(scores, 100 * contamination)
        
        # Prepare model metadata
        model_metadata = {
            'training_date': datetime.utcnow().isoformat(),
            'n_samples': X.shape[0],
            'n_features': X.shape[1],
            'contamination': contamination,
            'score_threshold': float(threshold),
            'parameters': model.get_params()
        }
        
        # Update the model reference
        self.model = {
            'model': model,
            'metadata': model_metadata,
            'threshold': threshold
        }
        
        # Persist the model if requested
        if persist:
            models_dir = Path(__file__).parent / 'models'
            models_dir.mkdir(exist_ok=True)
            
            # Save model
            model_path = models_dir / f'model_{int(datetime.utcnow().timestamp())}.joblib'
            joblib.dump(self.model, model_path)
            
            # Save metadata
            metadata_path = models_dir / 'model_metadata.json'
            with open(metadata_path, 'w') as f:
                json.dump(model_metadata, f, indent=2)
            
            self.logger.info(f"Model saved to {model_path}")
            model_metadata['model_path'] = str(model_path)
        
        return {
            'status': 'training_complete',
            'metrics': {
                'n_samples': X.shape[0],
                'n_features': X.shape[1],
                'contamination': contamination,
                'score_threshold': float(threshold)
            },
            'metadata': model_metadata
        }
    
    def load_model(self, model_path: Union[str, Path]) -> bool:
        """Load a pre-trained model from the specified path.
        
        Args:
            model_path: Path to the model file or directory
            
        Returns:
            bool: True if model was loaded successfully, False otherwise
        """
        try:
            # Placeholder for model loading logic
            # This would be implemented based on the specific ML framework used
            self.model = {
                'path': str(model_path),
                'loaded': True,
                'metadata': {}
            }
            self.logger.info(f"Model loaded from {model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model from {model_path}: {str(e)}")
            self.model = None
            return False
    
    def _apply_rules(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply all registered rules to the input data.
        
        Args:
            input_data: Dictionary containing event data with keys:
                - failed_logins: int
                - successful_logins: int
                - bytes_sent: int
                - bytes_recv: int
                - destination_port: int
                - hour_of_day: int
                - source_ip: str
                
        Returns:
            Dictionary with rule-based detection results
        """
        results = {
            'threat_score': 0.0,
            'matched_rules': [],
            'details': {}
        }
        
        # Check for brute force attempts
        if input_data.get('failed_logins', 0) > 5:
            score = min(1.0, input_data['failed_logins'] / 10.0)
            results['threat_score'] = max(results['threat_score'], score)
            results['matched_rules'].append({
                'rule_name': 'high_failed_logins',
                'description': f"High number of failed login attempts: {input_data['failed_logins']}",
                'severity': 'high',
                'score': score
            })
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 3389, 5900, 1433, 3306, 27017]
        if input_data.get('destination_port') in suspicious_ports:
            results['threat_score'] = max(results['threat_score'], 0.7)
            results['matched_rules'].append({
                'rule_name': 'suspicious_port',
                'description': f"Connection to potentially suspicious port: {input_data['destination_port']}",
                'severity': 'medium',
                'score': 0.7
            })
        
        # Check for unusual hours (outside 9 AM to 6 PM)
        hour = input_data.get('hour_of_day', 12)
        if hour < 9 or hour > 18:
            # More suspicious in the middle of the night
            night_factor = 1.5 if hour < 5 or hour > 22 else 1.0
            score = 0.5 * night_factor
            results['threat_score'] = max(results['threat_score'], min(score, 1.0))
            results['matched_rules'].append({
                'rule_name': 'unusual_hour',
                'description': f"Activity detected during unusual hours: {hour}:00",
                'severity': 'low',
                'score': min(score, 1.0)
            })
        
        return results
    
    def _apply_ml_detection(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply ML model to detect anomalies in the input data.
        
        Args:
            input_data: Dictionary containing event data
            
        Returns:
            Dictionary with ML detection results
        """
        if not self.model or 'model' not in self.model:
            return {
                'ml_score': 0.0,
                'ml_anomaly': False,
                'ml_details': 'No model loaded'
            }
        
        try:
            # Prepare feature vector in the correct order
            features = [
                input_data.get('failed_logins', 0),
                input_data.get('successful_logins', 0),
                input_data.get('bytes_sent', 0),
                input_data.get('bytes_recv', 0),
                input_data.get('destination_port', 0),
                input_data.get('hour_of_day', 12)
            ]
            
            # Get anomaly score (lower means more anomalous in IsolationForest)
            score = self.model['model'].score_samples([features])[0]
            threshold = self.model.get('threshold', -0.5)  # Default threshold
            
            return {
                'ml_score': float(score),
                'ml_anomaly': score < threshold,
                'ml_details': {
                    'threshold': float(threshold),
                    'feature_importance': self._get_feature_importance(features)
                }
            }
            
        except Exception as e:
            self.logger.error(f"ML detection error: {str(e)}", exc_info=True)
            return {
                'ml_score': 0.0,
                'ml_anomaly': False,
                'ml_details': f'Error: {str(e)}'
            }
    
    def _get_feature_importance(self, features: list) -> dict:
        """Get feature importance scores from the model if available."""
        if not self.model or 'model' not in self.model:
            return {}
            
        try:
            model = self.model['model']
            if hasattr(model, 'feature_importances_'):
                importance = model.feature_importances_
                feature_names = [
                    'failed_logins', 'successful_logins', 'bytes_sent',
                    'bytes_recv', 'destination_port', 'hour_of_day'
                ]
                return dict(zip(feature_names, importance.tolist()))
        except Exception:
            pass
            
        return {}
    
    def _analyze_results(self, rule_results: Dict[str, Any], 
                        ml_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze and combine results from rules and ML model.
        
        Args:
            rule_results: Results from rule-based detection
            ml_results: Results from ML-based detection
            
        Returns:
            Combined threat analysis results
        """
        # Start with default results
        combined = {
            'threat_detected': False,
            'confidence': 0.0,
            'threat_level': 'low',
            'threat_type': None,
            'details': {
                'rules': rule_results,
                'ml': ml_results
            },
            'recommended_actions': []
        }
        
        # Combine rule-based and ML scores
        rule_score = rule_results.get('threat_score', 0.0)
        ml_score = 0.0
        
        if ml_results.get('ml_anomaly', False):
            # Convert isolation forest score to 0-1 range where higher is more anomalous
            ml_score = 1.0 - ((ml_results.get('ml_score', 0.0) + 0.5) / 1.5)
            ml_score = max(0.0, min(1.0, ml_score))
        
        # Weighted combination (60% rules, 40% ML)
        combined['confidence'] = (rule_score * 0.6) + (ml_score * 0.4)
        
        # Determine threat level
        if combined['confidence'] > 0.7:
            combined['threat_level'] = 'high'
            combined['threat_detected'] = True
            combined['threat_type'] = 'security_breach_attempt'
            combined['recommended_actions'].extend([
                'Block source IP temporarily',
                'Require additional authentication',
                'Alert security team'
            ])
        elif combined['confidence'] > 0.4:
            combined['threat_level'] = 'medium'
            combined['threat_detected'] = True
            combined['threat_type'] = 'suspicious_activity'
            combined['recommended_actions'].append('Monitor closely')
        
        # Add additional context based on rules
        if rule_results.get('matched_rules'):
            combined['matched_rules'] = rule_results['matched_rules']
            
            # Check for specific high-severity rules
            high_severity_rules = [r for r in rule_results.get('matched_rules', []) 
                                 if r.get('severity') == 'high']
            if high_severity_rules and combined['threat_level'] != 'high':
                combined['threat_level'] = 'high'
                combined['threat_detected'] = True
                combined['threat_type'] = 'security_breach_attempt'
        
        return combined


class ThreatEngine:
    """Core engine for detecting and evaluating potential AI security threats."""
    
    def __init__(self):
        """Initialize the ThreatEngine with default configurations."""
        self.rules = []
        self.thresholds = {
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3
        }
    
    def add_rule(self, rule):
        """Add a new detection rule to the engine.
        
        Args:
            rule: A callable that takes input data and returns a threat score.
        """
        self.rules.append(rule)
    
    def evaluate(self, input_data):
        """Evaluate input data against all registered rules.
        
        Args:
            input_data: The data to evaluate for potential threats.
            
        Returns:
            dict: A dictionary containing threat scores and analysis results.
        """
        results = {
            'scores': [],
            'threat_detected': False,
            'threat_level': None,
            'details': []
        }
        
        for rule in self.rules:
            try:
                score, details = rule(input_data)
                results['scores'].append(score)
                results['details'].append(details)
            except Exception as e:
                # Log rule evaluation errors but continue with other rules
                continue
        
        if results['scores']:
            max_score = max(results['scores'])
            results['max_score'] = max_score
            
            if max_score >= self.thresholds['high']:
                results['threat_level'] = 'high'
                results['threat_detected'] = True
            elif max_score >= self.thresholds['medium']:
                results['threat_level'] = 'medium'
                results['threat_detected'] = True
            elif max_score >= self.thresholds['low']:
                results['threat_level'] = 'low'
                results['threat_detected'] = True
        
        return results
    
    def set_threshold(self, level, value):
        """Set the threshold for a specific threat level.
        
        Args:
            level (str): The threat level ('high', 'medium', or 'low').
            value (float): The threshold value (0.0 to 1.0).
        """
        if level in self.thresholds and 0 <= value <= 1:
            self.thresholds[level] = value
