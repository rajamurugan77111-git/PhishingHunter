"""Layers 5-6: weighted ensemble decision and final verdict."""
from .common import Any, DetectionLayer, Dict, RiskLevel


class Layer5_EnsembleDecision(DetectionLayer):
    """
    Layer 4: Ensemble Decision
    - Combines results from previous layers
    - Resolves conflicts between layers
    - Produces weighted risk score
    """
    
    def __init__(self):
        super().__init__("Ensemble Decision")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Combine results from previous layers."""
        results = {
            'layer': self.name,
            'weighted_risk_score': 0.0,
            'layer_scores': {},
            'consensus': None,
            'conflicts': []
        }
        
        try:
            if not context or 'layer_results' not in context:
                results['weighted_risk_score'] = 50
                results['consensus'] = "ERROR"
                results['conflicts'].append("No layer results found")
                return results
            
            layer_results = context['layer_results']
            
            # Calculate weighted risk score
            total_weight = 0
            weighted_score = 0
            layer_votes = {'phishing': 0, 'legitimate': 0, 'unknown': 0}
            
            # Track scores for each layer
            for layer_result in layer_results:
                layer_name = layer_result.get('layer', 'Unknown')
                risk_score = layer_result.get('risk_score', 0)
                weight = layer_result.get('weight', 1.0)
                
                # Add to weighted score
                weighted_score += risk_score * weight
                total_weight += weight
                
                # Record layer score
                results['layer_scores'][layer_name] = risk_score
                
                # Determine layer vote
                if risk_score >= 60:  # High risk
                    layer_votes['phishing'] += 1
                elif risk_score <= 30:  # Low risk
                    layer_votes['legitimate'] += 1
                else:
                    layer_votes['unknown'] += 1
            # Calculate final weighted score
            if total_weight > 0:
                results['weighted_risk_score'] = weighted_score / total_weight
            else:
                results['weighted_risk_score'] = 50
            
            # Determine consensus
            if layer_votes['phishing'] > layer_votes['legitimate'] + layer_votes['unknown']:
                results['consensus'] = "PHISHING"
            elif layer_votes['legitimate'] > layer_votes['phishing'] + layer_votes['unknown']:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['phishing'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['legitimate'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "PHISHING"
            else:
                results['consensus'] = "UNCERTAIN"
            
            # Check for conflicts
            if layer_votes['phishing'] > 0 and layer_votes['legitimate'] > 0:
                results['conflicts'].append("Layers disagree on classification")
            
            # Check for strong ML disagreement
            ml_result = None
            for layer_result in layer_results:
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction == 'phishing' and results['weighted_risk_score'] < 40:
                        results['conflicts'].append("ML says phishing but other layers disagree")
                    elif ml_prediction == 'legitimate' and results['weighted_risk_score'] > 60:
                        results['conflicts'].append("ML says legitimate but other layers disagree")
                    ml_result = layer_result
                    break
            
            # If ML is very confident, increase its influence
            if ml_result and 'confidence_scores' in ml_result:
                ml_confidence = max(ml_result['confidence_scores'].values()) if ml_result['confidence_scores'] else 0
                if ml_confidence > 0.9:  # Very high confidence
                    ml_prediction = ml_result.get('ml_prediction')
                    if ml_prediction == 'phishing':
                        results['weighted_risk_score'] = max(results['weighted_risk_score'], 
                                                            results['weighted_risk_score'] * 1.2)  # Increase by 20%
                    elif ml_prediction == 'legitimate':
                        results['weighted_risk_score'] = min(results['weighted_risk_score'], 
                                                           results['weighted_risk_score'] * 0.8)  # Decrease by 20%
            
        except Exception as e:
            results['weighted_risk_score'] = 50
            results['consensus'] = "ERROR"
            results['conflicts'].append(f"Ensemble error: {str(e)}")
        
        return results


class Layer6_FinalVerdict(DetectionLayer):
    """
    Layer 5: Final Verdict
    - Determines final risk level
    - Provides recommendations
    - Aggregates warnings and details
    """
    
    def __init__(self):
        super().__init__("Final Verdict")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate final verdict and recommendations."""
        results = {
            'final_verdict': RiskLevel.ERROR,
            'risk_percentage': 50,
            'confidence': 0.0,
            'recommendations': [],
            'summary': {},
            'early_termination': False
        }
        
        try:
            if not context:
                results['final_verdict'] = RiskLevel.ERROR
                results['risk_percentage'] = 50
                results['recommendations'].append("Analysis failed - insufficient data")
                return results
            
            # Check for early termination
            if 'final_result' in context and context['final_result'].get('early_termination', False):
                return context['final_result']
            
            # Get ensemble result
            ensemble_result = context.get('ensemble_result', {})
            risk_score = ensemble_result.get('weighted_risk_score', 50)
            consensus = ensemble_result.get('consensus', 'UNCERTAIN')
            conflicts = ensemble_result.get('conflicts', [])
            
            # Set risk percentage
            results['risk_percentage'] = risk_score
            
            # Determine confidence based on conflicts
            if not conflicts:
                confidence = 0.9  # High confidence if no conflicts
            elif len(conflicts) == 1:
                confidence = 0.7  # Medium confidence with one conflict
            else:
                confidence = 0.5  # Low confidence with multiple conflicts
                
            results['confidence'] = confidence
            
            # Determine final risk level - adjusted to catch critical threats better
            # More aggressive for IP addresses, brand impersonation, and blacklisted domains
            if risk_score >= 80:  # Decreased from 85
                results['final_verdict'] = RiskLevel.CRITICAL
            elif risk_score >= 55:  # Decreased from 65 - catch IP addresses and brand impersonation
                results['final_verdict'] = RiskLevel.HIGH
            elif risk_score >= 45:  # Decreased from 55
                results['final_verdict'] = RiskLevel.MEDIUM
            elif risk_score >= 25:  # Decreased from 35
                results['final_verdict'] = RiskLevel.LOW
            else:
                results['final_verdict'] = RiskLevel.SAFE
            
            # Generate recommendations based on risk level
            if results['final_verdict'] in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                results['recommendations'].extend([
                    "Do NOT proceed to this website",
                    "Do NOT enter any personal information",
                    "Do NOT download any files from this site"
                ])
            elif results['final_verdict'] == RiskLevel.MEDIUM:
                results['recommendations'].extend([
                    "Proceed with extreme caution",
                    "Verify the website through other channels before sharing information",
                    "Check the URL carefully for typos or unusual characters"
                ])
            elif results['final_verdict'] == RiskLevel.LOW:
                results['recommendations'].extend([
                    "Exercise normal caution",
                    "Verify the website if sharing sensitive information"
                ])
            else:  # SAFE
                results['recommendations'].extend([
                    "Website appears safe",
                    "Follow normal security practices"
                ])
            
            # Add any specific warnings from layers
            layer_flags = []
            for layer_result in context.get('layer_results', []):
                layer_flags.extend(layer_result.get('flags', []))
            
            if layer_flags:
                results['summary']['warnings'] = layer_flags[:5]  # Include top 5 warnings
                
            # If ML prediction exists, add to summary
            for layer_result in context.get('layer_results', []):
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction:
                        results['summary']['ml_prediction'] = ml_prediction
                    break
            
        except Exception as e:
            results['final_verdict'] = RiskLevel.ERROR
            results['risk_percentage'] = 50
            results['recommendations'].append(f"Analysis error: {str(e)}")
        
        return results
