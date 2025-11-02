"""
Sample Data Generator for NIDS Testing
Creates synthetic NSL-KDD formatted network traffic data
"""

import pandas as pd
import numpy as np

def generate_nsl_kdd_sample(n_samples=100, attack_ratio=0.3):
    """
    Generate synthetic NSL-KDD formatted data
    
    Args:
        n_samples: Number of samples to generate
        attack_ratio: Ratio of attack vs normal traffic
    
    Returns:
        pandas DataFrame with NSL-KDD features
    """
    np.random.seed(42)
    
    # NSL-KDD feature names (simplified - 30 most important features)
    feature_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
        'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
        'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
        'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
        'num_access_files', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate'
    ]
    
    data = []
    
    for i in range(n_samples):
        is_attack = np.random.rand() < attack_ratio
        
        if is_attack:
            # Generate attack-like pattern
            sample = {
                'duration': np.random.randint(0, 5000),
                'protocol_type': np.random.choice([0, 1, 2]),  # tcp, udp, icmp
                'service': np.random.choice([0, 1, 2, 3, 4]),
                'flag': np.random.choice([0, 1, 2, 3]),
                'src_bytes': np.random.randint(100, 100000),
                'dst_bytes': np.random.randint(0, 50000),
                'land': np.random.choice([0, 1]),
                'wrong_fragment': np.random.randint(0, 3),
                'urgent': np.random.randint(0, 3),
                'hot': np.random.randint(0, 30),
                'num_failed_logins': np.random.randint(0, 5),
                'logged_in': 0,
                'num_compromised': np.random.randint(0, 10),
                'root_shell': np.random.choice([0, 1]),
                'su_attempted': np.random.choice([0, 1]),
                'num_root': np.random.randint(0, 5),
                'num_file_creations': np.random.randint(0, 10),
                'num_shells': np.random.randint(0, 3),
                'num_access_files': np.random.randint(0, 10),
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': np.random.randint(1, 500),
                'srv_count': np.random.randint(1, 500),
                'serror_rate': np.random.rand(),
                'srv_serror_rate': np.random.rand(),
                'rerror_rate': np.random.rand(),
                'srv_rerror_rate': np.random.rand(),
                'same_srv_rate': np.random.rand(),
                'diff_srv_rate': np.random.rand(),
                'srv_diff_host_rate': np.random.rand()
            }
        else:
            # Generate normal traffic pattern
            sample = {
                'duration': np.random.randint(0, 100),
                'protocol_type': 0,  # mostly TCP
                'service': np.random.choice([0, 1, 2]),
                'flag': 0,  # normal flag
                'src_bytes': np.random.randint(10, 5000),
                'dst_bytes': np.random.randint(10, 5000),
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 1,
                'num_compromised': 0,
                'root_shell': 0,
                'su_attempted': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'is_host_login': 0,
                'is_guest_login': 0,
                'count': np.random.randint(1, 50),
                'srv_count': np.random.randint(1, 50),
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': np.random.rand() * 0.1,
                'srv_rerror_rate': np.random.rand() * 0.1,
                'same_srv_rate': np.random.rand() * 0.5 + 0.5,
                'diff_srv_rate': np.random.rand() * 0.2,
                'srv_diff_host_rate': np.random.rand() * 0.2
            }
        
        data.append(sample)
    
    df = pd.DataFrame(data)
    return df

if __name__ == "__main__":
    # Generate sample data
    print("🔄 Generating sample NSL-KDD data...")
    
    sample_data = generate_nsl_kdd_sample(n_samples=100, attack_ratio=0.3)
    
    # Save to CSV
    output_path = "data/sample_input.csv"
    sample_data.to_csv(output_path, index=False)
    
    print(f"✅ Generated {len(sample_data)} samples")
    print(f"📁 Saved to: {output_path}")
    print("\n📊 Sample statistics:")
    print(sample_data.describe())
    print("\n🎯 First 5 rows:")
    print(sample_data.head())