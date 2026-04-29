import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support, roc_auc_score
import joblib
import os

# Create models directory if it doesn't exist
if not os.path.exists('models'):
    os.makedirs('models')

def generate_synthetic_data(num_users=30, samples_per_user=50):
    """
    Generates synthetic behavioral features for multiple users.
    Features: avg_dwell, std_dwell, avg_flight, std_flight, typing_speed, avg_mouse_speed
    """
    data = []
    
    for user_id in range(num_users):
        # Each user has a unique "signature" defined by means and scales
        base_dwell = np.random.uniform(80, 150)
        base_flight = np.random.uniform(150, 300)
        base_speed = np.random.uniform(3, 8)
        base_mouse = np.random.uniform(20, 60)
        
        for _ in range(samples_per_user):
            row = {
                'user_id': user_id,
                'avg_dwell_time': np.random.normal(base_dwell, 10),
                'std_dwell_time': np.random.normal(15, 3),
                'avg_flight_time': np.random.normal(base_flight, 25),
                'std_flight_time': np.random.normal(40, 8),
                'typing_speed': np.random.normal(base_speed, 0.5),
                'avg_mouse_speed': np.random.normal(base_mouse, 5)
            }
            data.append(row)
            
    return pd.DataFrame(data)

def train_model():
    print("Generating synthetic behavioral dataset...")
    df = generate_synthetic_data()
    
    X = df.drop('user_id', axis=1)
    y = df['user_id']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training Random Forest Classifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)
    
    # Standard metrics
    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='macro')
    
    # AUC Score (Multi-class One-Vs-Rest)
    auc = roc_auc_score(pd.get_dummies(y_test), y_prob, multi_class='ovr', average='macro')
    
    print("\n" + "="*30)
    print("   MODEL EVALUATION RESULTS")
    print("="*30)
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC AUC:   {auc:.4f}")
    print("="*30)
    
    print("\nClassification Report Snippet (First 5 users):")
    print(classification_report(y_test, y_pred, target_names=[f"User_{i}" for i in range(30)], labels=list(range(5))))
    
    print("\nFeature Importances:")
    for feature, importance in zip(X.columns, clf.feature_importances_):
        print(f"  {feature}: {importance:.4f}")
    
    # Save the model
    model_path = 'models/bunkvauth_model.joblib'
    joblib.dump(clf, model_path)
    print(f"\nModel saved to {model_path}")

if __name__ == "__main__":
    train_model()
