"""Layer 4: machine-learning URL classification."""
from .common import Any, DetectionLayer, Dict, _HERE, datetime, json, logger, os
from .ml_model import load_model, predict_with_ml


def _deployed_model_accuracy(default: float) -> float:
    """Held-out accuracy recorded by the training script (falls back to an estimate)."""
    try:
        with open(os.path.join(_HERE, 'models', 'evaluation_results.json')) as fh:
            return float(json.load(fh).get('accuracy', default))
    except Exception:
        return default


class Layer4_MLClassification(DetectionLayer):
    """
    Layer 3: Machine Learning Classification
    - Uses trained ML model to classify URLs
    - Provides confidence scores for phishing probability
    """
    
    def __init__(self):
        super().__init__("ML Classification", weight=1.5)  # Higher weight for ML predictions
        self.model = None
        self.vectorizer = None
        self.model_type = "Unknown"
        self.fallback_mode = False
        self._load_model()
    
    def _load_model(self):
        """Load ML model and vectorizer."""
        try:
            self.model, self.vectorizer = load_model()
            if self.model is not None and self.vectorizer is not None:
                # Check if it's our fallback model
                if hasattr(self.model, 'model_type') and self.model.model_type == "RandomForest_Fallback":
                    logger.info("Using fallback Random Forest model for ML classification")
                    self.model_type = "RandomForest_Fallback"
                    self.fallback_mode = True
                else:
                    self.model_type = getattr(self.model, 'model_type', type(self.model).__name__)
                    logger.info(f"ML model ({self.model_type}) and vectorizer loaded successfully")
            else:
                logger.warning("ML model or vectorizer not loaded")
                self.enabled = False
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.enabled = False
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL using ML model."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': []
        }
        
        try:
            if not self.model or not self.vectorizer:
                results['flags'].append("ML model not available")
                results['risk_score'] = 0
                return results
            
            # Start timing for inference
            start_time = datetime.now()
            
            # Get ML prediction
            prediction = predict_with_ml(url, self.model, self.vectorizer)
            
            # End timing
            inference_time = (datetime.now() - start_time).total_seconds()
            
            if prediction is None:
                results['flags'].append("ML prediction failed")
                results['risk_score'] = 30
                return results
            
            # Extract information from prediction
            is_phishing = prediction['prediction'] == 'phishing'
            confidence = prediction.get('confidence', 0)
            confidence_scores = prediction.get('confidence_scores', {})
            
            # Add results
            results['ml_prediction'] = prediction['prediction']
            results['confidence_scores'] = confidence_scores
            results['inference_time'] = inference_time
            results['model_info'] = {
                'type': self.model_type,
                'fallback_mode': self.fallback_mode,
                'accuracy': _deployed_model_accuracy(0.85 if self.fallback_mode else 0.92)
            }
            
            # Set risk score based on phishing probability
            if is_phishing:
                phish_confidence = confidence_scores.get('phishing', confidence)
                # Scale to risk score from 0-100
                results['risk_score'] = min(100, phish_confidence * 100)
                
                # Add flags based on confidence
                if phish_confidence > 0.8:
                    results['flags'].append("High probability of phishing")
                elif phish_confidence > 0.6:
                    results['flags'].append("Medium probability of phishing")
                else:
                    results['flags'].append("Low probability of phishing")
            else:
                # If legitimate, risk score is inverse of legitimate confidence
                legit_confidence = confidence_scores.get('legitimate', 1 - confidence)
                results['risk_score'] = min(100, (1 - legit_confidence) * 80)  # Cap at 80 for negative predictions
            
            # Add model info
            try:
                model_type = "RandomForest"
                if "XGBClassifier" in str(type(self.model)):
                    model_type = "XGBoost"
                
                # Check if model uses GPU
                gpu_accelerated = False
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    if 'tree_method' in params:
                        gpu_accelerated = 'gpu' in params['tree_method']
                
                results['model_info'] = {
                    'type': model_type,
                    'accuracy': 0.8147,  # Placeholder - should come from evaluation
                    'gpu_accelerated': gpu_accelerated
                }
            except:
                # Ignore if model info collection fails
                pass
            
        except Exception as e:
            results['flags'].append(f"ML classification error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results
