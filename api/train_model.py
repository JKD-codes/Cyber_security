import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

def generate_synthetic_dataset():
    # 0 = Safe, 1 = Scam
    data = [
        # Safe Examples
        ("Your electricity bill for the month of July is Rs 1200. Please pay by the due date.", 0),
        ("Hey man, are we still on for the movie tonight?", 0),
        ("Your Amazon order has been shipped and will arrive on Friday.", 0),
        ("Meeting is rescheduled to 3 PM tomorrow.", 0),
        ("OTP for your transaction is 492011. Do not share this.", 0),
        ("Dear Customer, your bank statement for March is ready to view online.", 0),
        ("Don't forget to submit your KYC documents by next week at the branch.", 0),
        ("Happy birthday! Have a great day.", 0),
        ("Your Flipkart delivery is out for delivery today.", 0),
        ("Please verify your email address by clicking this link: https://google.com/verify", 0),
        ("This is a reminder that your subscription will renew in 3 days.", 0),
        ("The server has been updated successfully.", 0),
        ("Your salary has been credited to your account ending in 1234.", 0),
        ("Just arrived at the hotel, will call you later.", 0),
        ("Can you send me the report by EOD?", 0),
        
        # Scam / Phishing Examples
        ("URGENT: Your electricity connection will be suspended tonight. Call this number to update KYC immediately.", 1),
        ("Dear Customer, your SBI account is blocked. Please click here to update your PAN card: http://sbi-kyc.xyz", 1),
        ("Congratulations! You have won a lottery of Rs 25,00,000. Claim your prize money now by sending Rs 5000 processing fee.", 1),
        ("Your Paytm account will be blocked today due to pending KYC. Click http://paytrn-rewards.xyz to complete KYC.", 1),
        ("Your income tax refund of Rs 45,000 is approved. Please provide your bank details to claim it.", 1),
        ("Warning! Unauthorised login attempt on your Apple ID. Verify your credentials here immediately.", 1),
        ("We noticed suspicious activity on your HDFC credit card. Please share your OTP to cancel the transaction.", 1),
        ("Get an instant personal loan of up to 5 Lakhs with zero documentation! Click here to apply: http://loan-now.tk", 1),
        ("Your Amazon account has been locked. Verify your identity to restore access.", 1),
        ("You have an uncollected package waiting at the post office. Pay shipping fee here.", 1),
        ("URGENT action required: Your Aadhaar card has been suspended. Click link to reactivate.", 1),
        ("Special Bonus! You have received Rs 500 in your wallet. Click to accept the reward.", 1),
        ("Your WhatsApp account will expire in 24 hours. Send this message to 10 people to keep it free.", 1),
        ("Dear user, please update your bank details via this link to continue using services.", 1),
        ("Your account has been hacked. Send Bitcoin to this address to prevent data leak.", 1)
    ]
    
    # Duplicate data to give the model slightly more volume to train on (simulating a larger dataset)
    extended_data = data * 50
    
    df = pd.DataFrame(extended_data, columns=["text", "label"])
    return df

def train_and_save_model():
    print("Generating synthetic dataset...")
    df = generate_synthetic_dataset()
    
    # Feature extraction
    print("Training TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X = vectorizer.fit_transform(df['text'])
    y = df['label']
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate
    predictions = model.predict(X_test)
    print("\nModel Accuracy:", accuracy_score(y_test, predictions))
    print("\nClassification Report:\n", classification_report(y_test, predictions))
    
    # Ensure models directory exists
    os.makedirs("models", exist_ok=True)
    
    # Save models
    print("\nSaving models to api/models/...")
    joblib.dump(vectorizer, 'models/vectorizer.pkl')
    joblib.dump(model, 'models/cyber_model.pkl')
    print("Training complete! Models saved successfully.")

if __name__ == "__main__":
    train_and_save_model()
