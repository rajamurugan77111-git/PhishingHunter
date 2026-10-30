"""Loading the URL model and running ML predictions (with feature-based fallback)."""
from .common import Any, Dict, Tuple, joblib, json, logger, os, re, urllib
from .url_heuristics import extract_features, features_to_vector, rule_based_classification


def load_model() -> Tuple[Any, Any]:
    """
    Load a pre-trained machine learning model and vectorizer for phishing detection.
    
    Returns:
        Tuple[Any, Any]: The loaded ML model and vectorizer, or (None, None) if loading fails
    """
    try:
        # Try multiple possible locations for the models
        possible_model_dirs = [
            os.path.join(os.path.dirname(__file__), 'models'),  # Same directory as the script
            'models',  # Top-level models directory
            os.path.join(os.path.abspath(os.path.dirname(__file__)), 'models')  # Absolute path
        ]
        
        # Try each possible location
        for models_dir in possible_model_dirs:
            model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
            vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
        
            if os.path.exists(model_path):
                try:
                    logger.info(f"Attempting to load model from {model_path}")
                    
                    # Load model with error handling
                    model = joblib.load(model_path)
                    
                    # Validate model has required methods
                    if not hasattr(model, 'predict'):
                        logger.error("Loaded model doesn't have predict method")
                        continue
                    
                    # Test model prediction capability
                    try:
                        # Create a dummy test to check if model works
                        test_data = [[0] * 10]  # Dummy feature vector
                        _ = model.predict(test_data)
                        logger.info("Model prediction test passed")
                    except Exception as test_error:
                        logger.warning(f"Model prediction test failed: {test_error}")
                        # Continue loading but mark as potentially problematic
                    
                    # Check if vectorizer exists, if not we'll create a dummy one
                    if os.path.exists(vectorizer_path):
                        try:
                            vectorizer = joblib.load(vectorizer_path)
                            logger.info("Vectorizer loaded successfully")
                        except Exception as e:
                            logger.warning(f"Error loading vectorizer: {e}, creating dummy vectorizer")
                            # Create dummy vectorizer
                            from sklearn.feature_extraction.text import TfidfVectorizer
                            vectorizer = TfidfVectorizer(
                                analyzer='char_wb',
                                ngram_range=(3, 5),
                                max_features=10000
                            )
                            logger.warning("Using dummy vectorizer - ML predictions may be unreliable")
                    else:
                        # Create dummy vectorizer if file doesn't exist
                        from sklearn.feature_extraction.text import TfidfVectorizer
                        vectorizer = TfidfVectorizer(
                            analyzer='char_wb',
                            ngram_range=(3, 5),
                            max_features=10000
                        )
                        logger.warning("Vectorizer file not found, created dummy vectorizer")
                    
                    # Check if model has the problematic attributes
                    if hasattr(model, 'estimators_'):
                        logger.info("Model has estimators_ attribute - should work correctly")
                    else:
                        logger.warning("Model missing estimators_ attribute - may indicate compatibility issues")
                    
                    # Check scikit-learn version compatibility
                    try:
                        import sklearn
                        logger.info(f"Scikit-learn version: {sklearn.__version__}")
                    except:
                        pass
                    
                    logger.info(f"Successfully loaded ML model and vectorizer from {models_dir}")
                    
                    # Load evaluation results if available
                    results_path = os.path.join(models_dir, 'evaluation_results.json')
                    if os.path.exists(results_path):
                        try:
                            with open(results_path, 'r') as f:
                                results = json.load(f)
                            logger.info(f"Model accuracy: {results.get('accuracy', 'unknown')}")
                            if results.get('compatible', False):
                                logger.info("Model marked as compatible")
                            else:
                                logger.warning("Model compatibility not verified")
                        except Exception as json_error:
                            logger.warning(f"Could not load evaluation results: {json_error}")
                    
                    return model, vectorizer
                    
                except Exception as e:
                    logger.error(f"Error loading model from {model_path}: {e}")
                    logger.error(f"This may be due to scikit-learn version incompatibility")
                    logger.info("Consider running fix_model_error.py to retrain with compatible format")
                    continue
        
        # If we get here, we couldn't find the model in any location
        logger.warning(f"ML model files not found in any of these locations: {possible_model_dirs}")
        logger.info("To fix this:")
        logger.info("1. Run 'python fix_model_error.py' to retrain the model")
        logger.info("2. Or run 'python training/train_url_model.py' to train from scratch")
        logger.info("3. Make sure the dataset file exists in the project directory")
        
    except Exception as e:
        logger.error(f"Could not load model: {e}")
        logger.info("Suggestion: Run 'python fix_model_error.py' to create a compatible model")
    
    return None, None


def predict_with_ml(url: str, model: Any, vectorizer: Any) -> Dict[str, Any]:
    """
    Use the trained ML model to predict if a URL is phishing.
    
    Args:
        url (str): URL to analyze
        model: Trained ML model
        vectorizer: Fitted TF-IDF vectorizer
        
    Returns:
        Dict[str, Any]: Prediction results with confidence scores
    """
    try:
        # Check if model is our fallback model or has issues
        is_fallback = hasattr(model, 'model_type') and model.model_type == "RandomForest_Fallback"
        
        # Try regular ML prediction first
        try:
            # Regular approach: Transform URL using the vectorizer
            url_vec = vectorizer.transform([url])
            
            # Get prediction and confidence with error handling
            prediction = model.predict(url_vec)[0]
            
            # Try to get probability scores with fallback
            try:
                confidence_scores = model.predict_proba(url_vec)[0]
            except AttributeError as e:
                logger.warning(f"Model predict_proba failed: {e}, using fallback confidence")
                # Create fallback confidence scores
                prediction_value = float(prediction)
                if prediction_value == 1:  # phishing
                    confidence_scores = [0.2, 0.8]  # low legit, high phish
                else:  # legitimate
                    confidence_scores = [0.8, 0.2]  # high legit, low phish
            
            return {
                'prediction': 'phishing' if prediction == 1 else 'legitimate',
                'confidence': float(max(confidence_scores)),
                'confidence_scores': {
                    'legitimate': float(confidence_scores[0]),
                    'phishing': float(confidence_scores[1])
                },
                'method': 'machine_learning'
            }
            
        except (AttributeError, ValueError, TypeError) as ml_error:
            logger.warning(f"ML prediction failed ({ml_error}), using feature-based fallback")
            # Fall back to feature-based prediction
            pass
        
        # Fallback approach: Use feature extraction
        logger.info("Using feature-based fallback prediction")
        try:
            # Extract features for fallback model
            features = extract_features(url)
            # Convert to vector
            feature_vector = features_to_vector(features)
            
            # Check if this looks like a legitimate site first
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Legitimate domain patterns
            legitimate_domains = {
                'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 
                'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
                'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
                'wikipedia.org', 'bbc.com', 'cnn.com', 'netflix.com', 'spotify.com'
            }
            
            # Check for exact match or subdomain of legitimate sites
            is_likely_legitimate = any(
                domain == legit_domain or domain.endswith('.' + legit_domain)
                for legit_domain in legitimate_domains
            )
            
            if is_likely_legitimate:
                return {
                    'prediction': 'legitimate',
                    'confidence': 0.85,
                    'confidence_scores': {
                        'legitimate': 0.85,
                        'phishing': 0.15
                    },
                    'method': 'whitelist_fallback',
                    'reason': 'Recognized legitimate domain'
                }
            
            # Rule-based prediction using feature scores with more conservative thresholds
            feature_score = sum(feature_vector)
            max_score = len(feature_vector) * 2  # Theoretical maximum
            
            # Normalize score and determine prediction
            normalized_score = min(1.0, feature_score / max_score)
            
            # Be much more conservative - only flag as phishing if very suspicious
            if normalized_score > 0.8:  # Increased threshold
                prediction = 1  # phishing
                phish_confidence = min(0.9, 0.7 + (normalized_score * 0.2))
            elif normalized_score > 0.65:  # Increased threshold
                prediction = 1  # suspicious, classify as phishing
                phish_confidence = 0.65
            else:
                prediction = 0  # legitimate
                phish_confidence = max(0.1, normalized_score * 0.4)  # Lower base risk
            
            legit_confidence = 1 - phish_confidence
            confidence_scores = [legit_confidence, phish_confidence]
            
            return {
                'prediction': 'phishing' if prediction == 1 else 'legitimate',
                'confidence': float(max(confidence_scores)),
                'confidence_scores': {
                    'legitimate': float(confidence_scores[0]),
                    'phishing': float(confidence_scores[1])
                },
                'method': 'feature_based_conservative',
                'feature_score': feature_score,
                'normalized_score': normalized_score
            }
            
        except Exception as fe:
            logger.error(f"Feature-based fallback failed: {fe}")
            # Final fallback to rule-based classification
            pass
        # Final rule-based fallback
        try:
            features = extract_features(url)
            result = rule_based_classification(features)
            return {
                'prediction': result['prediction'],
                'confidence': float(result['confidence']),
                'confidence_scores': {
                    'legitimate': float(1 - result['confidence']) if result['prediction'] == 'phishing' else float(result['confidence']),
                    'phishing': float(result['confidence']) if result['prediction'] == 'phishing' else float(1 - result['confidence'])
                },
                'method': 'rule_based_fallback'
            }
        except Exception as re:
            logger.error(f"Rule-based fallback also failed: {re}")
            # Return safe default prediction
            return {
                'prediction': 'legitimate',
                'confidence': 0.5,
                'confidence_scores': {
                    'legitimate': 0.5,
                    'phishing': 0.5
                },
                'method': 'default_safe'
            }
            
    except Exception as e:
        logger.error(f"Complete ML prediction failure: {e}")
        # Return safe default
        return {
            'prediction': 'legitimate',
            'confidence': 0.5,
            'confidence_scores': {
                'legitimate': 0.5,
                'phishing': 0.5
            },
            'method': 'error_default'
        }
