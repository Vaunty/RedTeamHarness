"""geometry.py - Linear algebra engine for vector-space analysis of prompt embeddings.
Implements manual PCA via SVD, cosine similarity, difference-of-means attack direction,
and visualization utilities.
"""
import os
import numpy as np
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, accuracy_score

def calculate_cosine_similarity(X):
    """
    Computes the cosine similarity matrix for a matrix X of shape (n, d).
    Since embeddings from core/embed.py are already L2 normalized,
    this is equivalent to X @ X.T.
    """
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    Xn = X / norms
    return Xn @ Xn.T

def pca(X, k=2):
    """
    Performs Principal Component Analysis (PCA) using Singular Value Decomposition (SVD).
    
    Args:
        X: Matrix of shape (n, d).
        k: Number of dimensions to project to.
        
    Returns:
        Z: Projected matrix of shape (n, k).
        var_explained: Array of shape (k,) showing the proportion of variance explained by each component.
        components: Principal directions of shape (k, d).
    """
    mean = X.mean(axis=0)
    Xc = X - mean
    
    U, s, Vt = np.linalg.svd(Xc, full_matrices=False)
    components = Vt[:k]
    Z = Xc @ components.T
    
    eigenvalues = s**2
    total_variance = np.sum(eigenvalues)
    if total_variance > 0:
        var_explained = (eigenvalues / total_variance)[:k]
    else:
        var_explained = np.zeros(k)
        
    return Z, var_explained, components

def compute_difference_of_means_direction(X, y):
    """
    Computes the "difference-of-means" direction separating class 1 (attacks) and class 0 (benign).
    This is the unit vector pointing from the benign centroid to the attack centroid.
    
    Args:
        X: Embeddings of shape (n, d).
        y: Labels of shape (n,) where 1=attack, 0=benign.
        
    Returns:
        w: Normalized direction vector of shape (d,).
    """
    X_attack = X[y == 1]
    X_benign = X[y == 0]
    
    if len(X_attack) == 0 or len(X_benign) == 0:
        raise ValueError("Both attack (1) and benign (0) samples must be present.")
        
    mean_attack = X_attack.mean(axis=0)
    mean_benign = X_benign.mean(axis=0)
    
    w = mean_attack - mean_benign
    norm = np.linalg.norm(w)
    if norm > 0:
        w = w / norm
    return w

def train_linear_probe(X, y):
    """
    Trains a Logistic Regression classifier on embeddings X and labels y.
    Used as an optimal linear decision boundary cross-check for the difference-of-means.
    
    Args:
        X: Embeddings of shape (n, d).
        y: Labels of shape (n,).
        
    Returns:
        clf: Trained LogisticRegression classifier.
        coef_normed: Normalized coefficient vector of shape (d,).
        acc: Training accuracy.
    """
    clf = LogisticRegression(max_iter=1000, C=1.0)
    clf.fit(X, y)
    
    coef = clf.coef_[0]
    norm = np.linalg.norm(coef)
    if norm > 0:
        coef_normed = coef / norm
    else:
        coef_normed = coef
        
    y_pred = clf.predict(X)
    acc = accuracy_score(y, y_pred)
    
    return clf, coef_normed, acc

def plot_2d_projection(Z, y, title="PCA Prompt Space Projection", output_path=None):
    """
    Plots a 2D projection of prompts, colored by label.
    
    Args:
        Z: 2D projected coordinates of shape (n, 2).
        y: Labels of shape (n,) where 1=attack, 0=benign.
        title: Title of the plot.
        output_path: If specified, saves the plot to this path.
    """
    plt.figure(figsize=(10, 8), facecolor='#16161f')
    ax = plt.axes()
    ax.set_facecolor('#16161f')
    
    plt.grid(True, color=(1.0, 1.0, 1.0, 0.05), linestyle='--', zorder=0)
    
    benign_idx = (y == 0)
    attack_idx = (y == 1)
    
    plt.scatter(
        Z[benign_idx, 0], Z[benign_idx, 1],
        color='#00ff88', label='Benign Prompts',
        alpha=0.7, edgecolors='none', s=50, zorder=3
    )
    plt.scatter(
        Z[attack_idx, 0], Z[attack_idx, 1],
        color='#ff0055', label='Attack Prompts',
        alpha=0.7, edgecolors='none', s=50, zorder=3
    )
    
    plt.title(title, color='#e8e8ed', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel("PC 1", color='#8a8a9a', fontsize=10)
    plt.ylabel("PC 2", color='#8a8a9a', fontsize=10)
    
    ax.tick_params(colors='#8a8a9a', labelsize=9)
    for spine in ax.spines.values():
        spine.set_color((1.0, 1.0, 1.0, 0.1))
        
    legend = plt.legend(facecolor='#1b1b22', edgecolor=(1.0, 1.0, 1.0, 0.1), loc='best')
    for text in legend.get_texts():
        text.set_color('#e8e8ed')
        text.set_fontsize(9)
        
    plt.tight_layout()
    
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        plt.savefig(output_path, dpi=150, facecolor='#16161f', edgecolor='none')
        plt.close()
    else:
        plt.show()
