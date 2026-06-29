"""train_detector.py - Training and calibration script for the embedding-based attack detector.
Loads attack prompts, pairs them with benign control prompts, computes embeddings,
projects them using PCA via SVD, trains a linear classifier, and saves the weights/thresholds.
"""
import os
import json
import numpy as np
from core.embed import embed
from core.geometry import (
    pca,
    compute_difference_of_means_direction,
    train_linear_probe,
    plot_2d_projection
)

BENIGN_PROMPTS = [
    "What is the capital of France?",
    "How do I cook spaghetti carbonara?",
    "Explain the concept of quantum computing in simple terms.",
    "Write a short poem about a rainy autumn afternoon.",
    "How can I improve my website's loading speed?",
    "What is the distance between the Earth and the Moon?",
    "Help me debug this python loop: for i in range(10): print(i)",
    "Write a polite email to my manager asking for feedback on my latest presentation.",
    "What are the main differences between Python and JavaScript?",
    "How does photosynthesis work in plants?",
    "Translate the word 'friendship' into Spanish, French, and Japanese.",
    "Give me a list of healthy breakfast ideas that don't use eggs.",
    "What is the history of the Great Wall of China?",
    "How do I change a flat tire on a standard sedan?",
    "Explain the difference between a virus and a bacterium.",
    "Write a summary of the book 'To Kill a Mockingbird'.",
    "What is the formula for the area of a circle?",
    "How can I reduce stress after a long workday?",
    "Explain the water cycle to a 10-year-old child.",
    "What is the role of the heart in the circulatory system?",
    "Provide a recipe for homemade chocolate chip cookies.",
    "What are the symptoms of seasonal allergies?",
    "How do I set up a basic git repository?",
    "Explain the concept of supply and demand in economics.",
    "Write a motivational quote to start the day.",
    "What are the main causes of ocean tides?",
    "How do I care for a houseplant like a monstera?",
    "Describe the key features of the Roman Empire.",
    "What is the average lifespan of a golden retriever?",
    "Write a riddle about time.",
    "How do I format a hard drive on Windows 11?",
    "What is the structure of an atom?",
    "Explain the rules of soccer/football briefly.",
    "How do I practice active listening in conversations?",
    "Write a paragraph describing a futuristic city in 2100."
]

def load_attack_prompts(probes_path="data/probes.jsonl"):
    """Extracts all attack user prompts from the existing probes file."""
    attacks = []
    if os.path.exists(probes_path):
        with open(probes_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        probe = json.loads(line)
                        if "user" in probe:
                            attacks.append(probe["user"])
                        elif "turns" in probe and isinstance(probe["turns"], list) and len(probe["turns"]) > 0:
                            # For multi-turn, use the final escalation turn
                            attacks.append(probe["turns"][-1])
                    except Exception as e:
                        print(f"[Warning] Failed to parse probe line: {e}")
    return list(set(attacks)) # De-duplicate

def main():
    print("=== Training Embedding Attack Detector ===")
    
    # 1. Load data
    attacks = load_attack_prompts()
    print(f"Loaded {len(attacks)} unique attack prompts from probes.")
    print(f"Using {len(BENIGN_PROMPTS)} hand-coded benign prompts as control.")
    
    # Save the labeled dataset for record keeping
    dataset_path = "data/labeled_prompts.jsonl"
    os.makedirs(os.path.dirname(dataset_path), exist_ok=True)
    with open(dataset_path, "w", encoding="utf-8") as f:
        for p in BENIGN_PROMPTS:
            f.write(json.dumps({"text": p, "label": 0}) + "\n")
        for p in attacks:
            f.write(json.dumps({"text": p, "label": 1}) + "\n")
    print(f"Saved compiled dataset to {dataset_path}")
    
    # Combine texts and labels
    texts = BENIGN_PROMPTS + attacks
    y = np.array([0] * len(BENIGN_PROMPTS) + [1] * len(attacks))
    
    # 2. Generate embeddings
    print("Generating sentence-transformers embeddings (all-MiniLM-L6-v2)...")
    X = embed(texts)
    print(f"Embedding matrix shape: {X.shape}")
    
    # 3. Perform PCA for visualization
    print("Performing SVD-based PCA projection to 2D...")
    Z, var_explained, _ = pca(X, k=2)
    print(f"Top 2 Principal Components explain {var_explained.sum():.1%} of variance.")
    print(f"  PC1: {var_explained[0]:.1%}, PC2: {var_explained[1]:.1%}")
    
    # Save PCA plot
    plot_path = "results/pca_projection.png"
    plot_2d_projection(Z, y, title=f"Prompt Space Projection (Variance Explained: {var_explained.sum():.1%})", output_path=plot_path)
    print(f"Saved PCA projection scatter plot to {plot_path}")
    
    # 4. Compute difference-of-means attack direction
    print("Computing difference-of-means attack direction...")
    w_dom = compute_difference_of_means_direction(X, y)
    
    # 5. Train linear probe classifier for comparison
    print("Training Logistic Regression linear probe...")
    _, w_probe, probe_acc = train_linear_probe(X, y)
    print(f"Linear Probe Training Accuracy: {probe_acc:.1%}")
    
    # Calculate similarity between DOM direction and optimal probe direction
    alignment = float(w_dom @ w_probe)
    print(f"Alignment (cosine similarity) between DOM and Probe direction: {alignment:.3f}")
    
    # 6. Choose model direction (prefer difference-of-means for pure LA simplicity,
    # or the learned probe if alignment is low. We'll use the learned probe for better accuracy).
    w = w_probe
    
    # Calculate scores (projections)
    scores = X @ w
    benign_scores = scores[y == 0]
    attack_scores = scores[y == 1]
    
    # Calibrate threshold to achieve 0% False Positive Rate on training benign prompts if possible,
    # or select a balanced threshold (midpoint between means).
    # Let's set it as the midpoint of the minimum attack score and maximum benign score.
    max_benign = np.max(benign_scores)
    min_attack = np.min(attack_scores)
    
    if min_attack > max_benign:
        # Perfectly separable!
        threshold = (max_benign + min_attack) / 2.0
        print("Data is perfectly linearly separable!")
    else:
        # Not perfectly separable, use midpoint of centroids
        threshold = float((benign_scores.mean() + attack_scores.mean()) / 2.0)
        
    print(f"Calibrated detection threshold: {threshold:.4f}")
    
    # Evaluate calibrated threshold on training set
    predictions = (scores > threshold).astype(int)
    final_acc = accuracy_score(y, predictions)
    false_positives = np.sum((predictions == 1) & (y == 0))
    false_negatives = np.sum((predictions == 0) & (y == 1))
    print(f"Final Detector Performance on Labeled Set:")
    print(f"  Accuracy: {final_acc:.1%}")
    print(f"  False Positives: {false_positives} / {len(BENIGN_PROMPTS)}")
    print(f"  False Negatives: {false_negatives} / {len(attacks)}")
    
    # Save the model
    model_path = "data/detector_model.npz"
    from core.detector import EmbeddingDetector
    detector = EmbeddingDetector(model_path=model_path)
    detector.save_model(w, threshold)
    print(f"Successfully saved detector weights and threshold to {model_path}")
    print("=== Training Complete ===")

if __name__ == "__main__":
    main()
