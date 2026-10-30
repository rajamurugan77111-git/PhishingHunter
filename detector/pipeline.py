"""LayeredPhishingDetector: runs the six detection layers in order."""
from .common import Any, Dict, RiskLevel, datetime, logger
from .decision import Layer5_EnsembleDecision, Layer6_FinalVerdict
from .layer1_validation import Layer1_BasicValidation
from .layer2_features import Layer2_FeatureAnalysis
from .layer3_content import Layer3_ContentAnalysis
from .layer4_ml import Layer4_MLClassification


class LayeredPhishingDetector:
    """
    Main class implementing the layered phishing detection system.
    """
    
    def __init__(self):
        # Initialize layers with error handling
        self.layers = []
        
        try:
            self.layers = [
                Layer1_BasicValidation(),
                Layer2_FeatureAnalysis(),
                Layer3_ContentAnalysis(),
                Layer4_MLClassification(),
                Layer5_EnsembleDecision(),
                Layer6_FinalVerdict()
            ]
            
            # Check which layers are enabled
            enabled_layers = [layer for layer in self.layers if layer.enabled]
            disabled_layers = [layer for layer in self.layers if not layer.enabled]
            
            logger.info(f"Initialized {len(enabled_layers)} detection layers successfully")
            if disabled_layers:
                logger.warning(f"Disabled layers: {[layer.name for layer in disabled_layers]}")
                
        except Exception as e:
            logger.error(f"Error initializing layers: {e}")
            # Create minimal fallback layers
            self.layers = [
                Layer1_BasicValidation(),
                Layer6_FinalVerdict()
            ]
            logger.warning("Using minimal layer configuration due to initialization errors")
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL through all detection layers with improved error handling.
        """
        analysis_results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'layer_results': [],
            'ensemble_result': {},
            'final_result': {},
            'processing_time': 0.0,
            'error': None
        }
        
        start_time = datetime.now()
        
        try:
            # Validate URL first
            if not url or not isinstance(url, str):
                raise ValueError("Invalid URL provided")
            
            # Pass URL through each enabled layer
            context = {}
            
            for i, layer in enumerate(self.layers):
                if not layer.enabled:
                    logger.debug(f"Layer {layer.name} is disabled, skipping")
                    continue
                
                try:
                    logger.debug(f"Processing layer {i+1}: {layer.name}")
                    
                    # Special handling for ensemble and final layers
                    if isinstance(layer, Layer5_EnsembleDecision):
                        context['layer_results'] = analysis_results['layer_results']
                        layer_result = layer.analyze(url, context)
                        analysis_results['ensemble_result'] = layer_result
                    
                    elif isinstance(layer, Layer6_FinalVerdict):
                        context['ensemble_result'] = analysis_results['ensemble_result']
                        context['layer_results'] = analysis_results['layer_results']
                        layer_result = layer.analyze(url, context)
                        analysis_results['final_result'] = layer_result
                    
                    else:
                        layer_result = layer.analyze(url, context)
                        if layer_result:
                            layer_result['weight'] = layer.weight
                            analysis_results['layer_results'].append(layer_result)
                        
                        # Store context for subsequent layers
                        if layer_result:
                            context[layer.name.lower().replace(' ', '_') + '_result'] = layer_result
                    
                    # Early termination for critical issues in Layer 1
                    if (isinstance(layer, Layer1_BasicValidation) and 
                        not layer_result.get('passed', True) and 
                        layer_result.get('risk_score', 0) > 80):
                        
                        logger.warning("Critical issues detected in Layer 1, terminating analysis")
                        analysis_results['final_result'] = {
                            'final_verdict': RiskLevel.CRITICAL,
                            'risk_percentage': layer_result['risk_score'],
                            'confidence': 0.9,
                            'early_termination': True,
                            'recommendations': [
                                "🚨 Critical security threat detected",
                                "🚨 DO NOT proceed with this URL"
                            ]
                        }
                        break
                        
                except Exception as layer_error:
                    logger.error(f"Error in layer {layer.name}: {layer_error}")
                    # Continue with other layers instead of failing completely
                    error_result = {
                        'layer': layer.name,
                        'risk_score': 30,  # Default moderate risk for errors
                        'flags': [f"Layer error: {str(layer_error)}"],
                        'weight': layer.weight,
                        'error': True
                    }
                    analysis_results['layer_results'].append(error_result)
            
            # Ensure we have a final result even if layers failed
            if not analysis_results.get('final_result'):
                # Create fallback final result
                avg_risk = 50  # Default
                if analysis_results['layer_results']:
                    risks = [lr.get('risk_score', 50) for lr in analysis_results['layer_results']]
                    avg_risk = sum(risks) / len(risks)
                
                analysis_results['final_result'] = {
                    'final_verdict': RiskLevel.MEDIUM if avg_risk > 40 else RiskLevel.LOW,
                    'risk_percentage': avg_risk,
                    'confidence': 0.5,
                    'recommendations': ["Analysis completed with limited data"],
                    'fallback_result': True
                }
        
        except Exception as e:
            logger.error(f"Critical error during analysis: {e}")
            analysis_results['error'] = str(e)
            analysis_results['final_result'] = {
                'final_verdict': RiskLevel.ERROR,
                'risk_percentage': 50,
                'confidence': 0.0,
                'recommendations': ["Analysis failed - treat with caution"],
                'error': str(e)
            }
        
        # Calculate processing time
        end_time = datetime.now()
        analysis_results['processing_time'] = (end_time - start_time).total_seconds()
        
        return analysis_results
    
    def get_quick_verdict(self, url: str) -> str:
        """Get a quick verdict for simple use cases."""
        results = self.analyze_url(url)
        final_result = results.get('final_result', {})
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        
        if isinstance(verdict, RiskLevel):
            return verdict.value
        return str(verdict)
