"""
Standalone Email Phishing Detection using Machine Learning
Author: Phishing Detection System
Description: Console-based email phishing detector using ML model
"""

import re
import pickle
import os
import sys
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

class EmailPhishingDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.pipeline = None
        self.feature_names = [
            'url_count', 'suspicious_words_count', 'urgency_words_count',
            'personal_info_requests', 'external_links', 'suspicious_domains',
            'has_attachments', 'spelling_errors', 'grammar_errors',
            'sender_reputation', 'text_length', 'caps_ratio'
        ]
        
        # Phishing indicators
        self.suspicious_words = [
            'urgent', 'immediate', 'act now', 'limited time', 'expire',
            'suspended', 'verify', 'confirm', 'update', 'click here',
            'download', 'winner', 'congratulations', 'free', 'prize',
            'lottery', 'inheritance', 'million', 'dollars', 'transfer',
            'bank', 'account', 'password', 'security', 'breach'
        ]
        
        self.urgency_words = [
            'urgent', 'immediate', 'asap', 'quickly', 'hurry',
            'deadline', 'expires', 'limited', 'act now', 'time sensitive'
        ]
        
        self.personal_info_words = [
            'ssn', 'social security', 'credit card', 'bank account',
            'routing number', 'pin', 'password', 'username', 'login',
            'personal information', 'date of birth', 'mother maiden name'
        ]
        
        self.suspicious_domains = [
            '.tk', '.ml', '.ga', '.cf', 'bit.ly', 'tinyurl',
            'suspicious-bank.com', 'fake-paypal.com', 'phishing-site.net'
        ]
        
        # Load or create model
        self.model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
        self.load_or_create_model()

    def extract_features(self, email_content, sender='', subject=''):
        """Extract features from email content"""
        features = {}
        text = f"{subject} {email_content} {sender}".lower()
        
        # URL count
        features['url_count'] = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
        
        # Suspicious words count
        features['suspicious_words_count'] = sum(1 for word in self.suspicious_words if word in text)
        
        # Urgency words count
        features['urgency_words_count'] = sum(1 for word in self.urgency_words if word in text)
        
        # Personal info requests
        features['personal_info_requests'] = sum(1 for word in self.personal_info_words if word in text)
        
        # External links (simplified)
        features['external_links'] = len(re.findall(r'click here|download|visit|go to', text))
        
        # Suspicious domains
        features['suspicious_domains'] = sum(1 for domain in self.suspicious_domains if domain in text)
        
        # Has attachments (keyword-based detection)
        features['has_attachments'] = 1 if any(word in text for word in ['attachment', 'attached', 'download', 'file']) else 0
        
        # Spelling errors (simplified - count common misspellings)
        misspellings = ['recieve', 'occured', 'seperate', 'definately', 'goverment']
        features['spelling_errors'] = sum(1 for word in misspellings if word in text)
        
        # Grammar errors (simplified - look for patterns)
        grammar_patterns = [r'\bi is\b', r'\byou was\b', r'\bthey was\b']
        features['grammar_errors'] = sum(1 for pattern in grammar_patterns if re.search(pattern, text))
        
        # Sender reputation (simplified)
        suspicious_senders = ['noreply', 'donotreply', 'admin', 'support', 'security']
        features['sender_reputation'] = 1 if any(sus in sender.lower() for sus in suspicious_senders) else 0
        
        # Text length
        features['text_length'] = len(email_content)
        
        # Caps ratio
        caps_count = sum(1 for c in email_content if c.isupper())
        features['caps_ratio'] = caps_count / len(email_content) if len(email_content) > 0 else 0
        
        return features

    def create_sample_dataset(self):
        """Create sample dataset for training"""
        # Sample phishing emails
        phishing_emails = [
            {
                'subject': 'URGENT: Your Account Will Be Suspended',
                'content': 'Dear Customer, Your account will be suspended immediately unless you verify your information. Click here to update your password and credit card details. Act now before it expires!',
                'sender': 'security@fake-bank.com',
                'label': 1
            },
            {
                'subject': 'Congratulations! You Won $1,000,000',
                'content': 'You have won the lottery! To claim your prize, please provide your social security number and bank account details. Download the form and send it back immediately.',
                'sender': 'winner@lottery-scam.tk',
                'label': 1
            },
            {
                'subject': 'Security Alert - Immediate Action Required',
                'content': 'We detected suspicious activity on your account. Verify your identity by providing your username, password, and PIN number. Time sensitive!',
                'sender': 'noreply@phishing-site.ml',
                'label': 1
            },
            {
                'subject': 'Bank Account Verification Needed',
                'content': 'Your bank account needs verification. Please confirm your routing number, account number, and social security number by clicking the link below.',
                'sender': 'admin@suspicious-bank.com',
                'label': 1
            },
            {
                'subject': 'Inheritance Fund Transfer',
                'content': 'You have inherited $5 million dollars from a distant relative. To transfer the funds, we need your personal information and bank details.',
                'sender': 'lawyer@inheritance-scam.ga',
                'label': 1
            }
        ]
        
        # Sample legitimate emails
        legitimate_emails = [
            {
                'subject': 'Welcome to Our Service',
                'content': 'Thank you for signing up for our newsletter. We will send you updates about our products and services.',
                'sender': 'welcome@legitimate-company.com',
                'label': 0
            },
            {
                'subject': 'Meeting Reminder',
                'content': 'This is a reminder about our meeting scheduled for tomorrow at 2 PM. Please let me know if you need to reschedule.',
                'sender': 'colleague@company.com',
                'label': 0
            },
            {
                'subject': 'Project Update',
                'content': 'Here is the latest update on our project. We have completed 75% of the work and are on track to meet the deadline.',
                'sender': 'manager@workplace.org',
                'label': 0
            },
            {
                'subject': 'Recipe of the Week',
                'content': 'This week we are featuring a delicious pasta recipe. Check out our website for the full instructions and ingredient list.',
                'sender': 'recipes@cooking-blog.net',
                'label': 0
            },
            {
                'subject': 'Order Confirmation',
                'content': 'Thank you for your order. Your items will be shipped within 2-3 business days. You will receive a tracking number once shipped.',
                'sender': 'orders@shopping-site.com',
                'label': 0
            }
        ]
        
        all_emails = phishing_emails + legitimate_emails
        
        # Extract features for all emails
        features_list = []
        labels = []
        texts = []
        
        for email in all_emails:
            features = self.extract_features(email['content'], email['sender'], email['subject'])
            features_list.append(features)
            labels.append(email['label'])
            texts.append(f"{email['subject']} {email['content']}")
        
        return features_list, labels, texts

    def train_model(self):
        """Train the phishing detection model"""
        print("🔄 Training phishing detection model...")
        
        # Get sample data
        features_list, labels, texts = self.create_sample_dataset()
        
        # Convert features to DataFrame
        df_features = pd.DataFrame(features_list)
        
        # Create TF-IDF features for text
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
        text_features = vectorizer.fit_transform(texts)
        
        # Combine numerical and text features
        combined_features = np.hstack([df_features.values, text_features.toarray()])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            combined_features, labels, test_size=0.3, random_state=42
        )
        
        # Train Random Forest model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"✅ Model trained with accuracy: {accuracy:.2f}")
        
        # Create pipeline
        self.pipeline = Pipeline([
            ('vectorizer', vectorizer),
            ('classifier', model)
        ])
        
        # Store components
        self.vectorizer = vectorizer
        self.model = model
        
        # Save model
        self.save_model()
        
        return accuracy

    def save_model(self):
        """Save the trained model"""
        model_data = {
            'pipeline': self.pipeline,
            'vectorizer': self.vectorizer,
            'model': self.model,
            'feature_names': self.feature_names
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"💾 Model saved to {self.model_path}")

    def load_model(self):
        """Load the trained model"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.pipeline = model_data['pipeline']
            self.vectorizer = model_data['vectorizer']
            self.model = model_data['model']
            self.feature_names = model_data['feature_names']
            
            print("✅ Model loaded successfully")
            return True
        except FileNotFoundError:
            print("❌ Model file not found")
            return False

    def load_or_create_model(self):
        """Load existing model or create new one"""
        if not self.load_model():
            print("🔧 Creating new model...")
            self.train_model()

    def predict_phishing(self, email_content, sender='', subject=''):
        """Predict if email is phishing"""
        if not self.model or not self.vectorizer:
            print("❌ Model not loaded properly")
            return None
        
        # Extract numerical features
        features = self.extract_features(email_content, sender, subject)
        numerical_features = np.array([list(features.values())]).reshape(1, -1)
        
        # Extract text features
        text = f"{subject} {email_content}"
        text_features = self.vectorizer.transform([text])
        
        # Combine features
        combined_features = np.hstack([numerical_features, text_features.toarray()])
        
        # Make prediction
        prediction = self.model.predict(combined_features)[0]
        probability = self.model.predict_proba(combined_features)[0]
        
        # Get feature importance for explanation
        feature_importance = self.get_feature_explanation(features, text)
        
        return {
            'is_phishing': bool(prediction),
            'phishing_probability': float(probability[1]),
            'legitimate_probability': float(probability[0]),
            'confidence': float(max(probability)),
            'features': features,
            'explanation': feature_importance
        }

    def get_feature_explanation(self, features, text):
        """Get explanation of why email was classified as phishing/legitimate"""
        explanations = []
        
        if features['suspicious_words_count'] > 0:
            explanations.append(f"Contains {features['suspicious_words_count']} suspicious words")
        
        if features['urgency_words_count'] > 0:
            explanations.append(f"Contains {features['urgency_words_count']} urgency indicators")
        
        if features['personal_info_requests'] > 0:
            explanations.append(f"Requests personal information ({features['personal_info_requests']} indicators)")
        
        if features['url_count'] > 2:
            explanations.append(f"Contains multiple URLs ({features['url_count']})")
        
        if features['suspicious_domains'] > 0:
            explanations.append(f"Contains suspicious domains ({features['suspicious_domains']})")
        
        if features['caps_ratio'] > 0.3:
            explanations.append(f"High use of capital letters ({features['caps_ratio']:.1%})")
        
        if features['spelling_errors'] > 0:
            explanations.append(f"Contains spelling errors ({features['spelling_errors']})")
        
        if features['sender_reputation'] == 1:
            explanations.append("Sender appears suspicious")
        
        return explanations

def main():
    """Main function for console interface"""
    print("🛡️  EMAIL PHISHING DETECTION SYSTEM")
    print("=" * 50)
    
    # Initialize detector
    detector = EmailPhishingDetector()
    
    while True:
        print("\n📧 Email Phishing Detector")
        print("1. Analyze Email")
        print("2. Retrain Model")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            print("\n📝 Enter Email Details:")
            print("-" * 30)
            
            subject = input("Subject: ").strip()
            sender = input("Sender: ").strip()
            
            print("Content (Press Enter twice to finish):")
            content_lines = []
            while True:
                line = input()
                if line == "":
                    break
                content_lines.append(line)
            
            content = "\n".join(content_lines)
            
            if not content.strip():
                print("❌ Email content cannot be empty!")
                continue
            
            print("\n🔍 Analyzing email...")
            
            # Analyze email
            result = detector.predict_phishing(content, sender, subject)
            
            if result:
                print("\n" + "=" * 50)
                print("📊 ANALYSIS RESULTS")
                print("=" * 50)
                
                if result['is_phishing']:
                    print("🚨 PHISHING DETECTED!")
                    print(f"❌ This email is likely PHISHING")
                else:
                    print("✅ LEGITIMATE EMAIL")
                    print(f"✅ This email appears LEGITIMATE")
                
                print(f"\n📈 Confidence: {result['confidence']:.1%}")
                print(f"🎯 Phishing Probability: {result['phishing_probability']:.1%}")
                print(f"✅ Legitimate Probability: {result['legitimate_probability']:.1%}")
                
                if result['explanation']:
                    print(f"\n🔍 Warning Indicators:")
                    for explanation in result['explanation']:
                        print(f"   • {explanation}")
                else:
                    print(f"\n✅ No suspicious indicators found")
                
                print(f"\n📋 Feature Analysis:")
                for feature, value in result['features'].items():
                    if value > 0:
                        print(f"   • {feature.replace('_', ' ').title()}: {value}")
            else:
                print("❌ Error analyzing email")
        
        elif choice == '2':
            print("\n🔄 Retraining model...")
            detector.train_model()
            print("✅ Model retrained successfully!")
        
        elif choice == '3':
            print("\n👋 Thank you for using Email Phishing Detector!")
            break
        
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        sys.exit(1)
