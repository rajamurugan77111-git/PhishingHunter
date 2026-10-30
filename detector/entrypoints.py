"""High-level helper entry points (classify_url, check_url_enhanced)."""
from .common import Any, Dict, logger
from .ml_model import predict_with_ml
from .url_heuristics import extract_features, get_recommendations, rule_based_classification


def classify_url(features: Dict[str, Any] = None, url: str = None, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Classify a URL as phishing or legitimate using both ML and rule-based methods.
    
    Args:
        features (Dict[str, Any]): Dictionary of extracted features (optional)
        url (str): URL to classify (required for ML method)
        model: Pre-trained ML model (optional)
        vectorizer: Fitted vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Classification result including prediction and confidence
    """
    try:
        # Try ML prediction first if model and URL are available
        if model is not None and vectorizer is not None and url is not None:
            ml_result = predict_with_ml(url, model, vectorizer)
            if ml_result is not None:
                # Also get rule-based prediction for comparison
                if features is None:
                    features = extract_features(url)
                rule_result = rule_based_classification(features)
                
                # Combine results
                ml_result['rule_based_prediction'] = rule_result['prediction']
                ml_result['rule_based_score'] = rule_result['phishing_score']
                ml_result['features'] = features
                
                return ml_result
        
        # Fall back to rule-based classification
        if features is None and url is not None:
            features = extract_features(url)
        elif features is None:
            raise ValueError("Either features or url must be provided")
            
        return rule_based_classification(features)
        
    except Exception as e:
        logger.error(f"Classification failed: {e}")
        # Return safe default
        return {
            'prediction': 'error',
            'confidence': 0.0,
            'method': 'error',
            'error': str(e)
        }


def check_url_enhanced(url: str, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Enhanced URL checking with detailed analysis.
    
    Args:
        url (str): URL to check
        model: ML model (optional)
        vectorizer: Vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Detailed analysis results
    """
    try:
        # Extract features
        features = extract_features(url)
        
        # Get classification
        classification = classify_url(features=features, url=url, model=model, vectorizer=vectorizer)
        
        # Calculate risk assessment
        risk_level = "LOW"
        if classification['prediction'] == 'phishing':
            if classification['confidence'] > 0.8:
                risk_level = "HIGH"
            elif classification['confidence'] > 0.6:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW-MEDIUM"
        
        return {
            'url': url,
            'risk_level': risk_level,
            'classification': classification,
            'features': features,
            'recommendations': get_recommendations(features, classification)
        }
        
    except Exception as e:
        logger.error(f"Enhanced URL check failed: {e}")
        return {
            'url': url,
            'risk_level': "ERROR",
            'error': str(e)
        }
