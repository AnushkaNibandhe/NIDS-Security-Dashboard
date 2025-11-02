from shared.inference import NIDSInference, generate_synthetic_traffic

print("🔥 Testing Attack Detection System")
print("="*70)

# Initialize
engine = NIDSInference()

# Generate attack-heavy data
print("\n📊 Generating synthetic traffic (70% attacks)...")
data = generate_synthetic_traffic(n_samples=30, attack_ratio=0.7)

# Predict
print("\n🔍 Running predictions...\n")
results = engine.batch_predict(data)

# Analyze results
attack_counts = {}
for r in results:
    attack_type = r['attack_type']
    attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

print("\n" + "="*70)
print("📊 DETECTION SUMMARY:")
print("="*70)

emojis = {'DoS': '🔴', 'Probe': '🟡', 'R2L': '🟠', 'U2R': '🔴', 'Normal': '✅'}
for attack in ['DoS', 'Probe', 'R2L', 'U2R', 'Normal']:
    count = attack_counts.get(attack, 0)
    percentage = (count/len(results)*100)
    emoji = emojis.get(attack, '⚪')
    bar = '█' * int(percentage/5)
    print(f"{emoji} {attack:10s}: {count:3d} ({percentage:5.1f}%) {bar}")

print("="*70)
print(f"\n✅ Total Attacks Detected: {len(results) - attack_counts.get('Normal', 0)} / {len(results)}")
print(f"✅ Attack Detection Rate: {(len(results) - attack_counts.get('Normal', 0))/len(results)*100:.1f}%")