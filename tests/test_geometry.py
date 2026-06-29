"""test_geometry.py - Tests for the linear algebra and PCA math functions.
Verifies hand-rolled PCA against scikit-learn PCA.
"""
import numpy as np
from sklearn.decomposition import PCA as sklearn_PCA
from core.geometry import pca

def test_pca_against_sklearn():
    # Generate some random high-dimensional data
    np.random.seed(42)
    n, d = 50, 10
    X = np.random.randn(n, d)
    
    # 1. Run our hand-rolled SVD-based PCA
    k = 3
    Z_hand, var_hand, components_hand = pca(X, k=k)
    
    # 2. Run scikit-learn's PCA
    pca_sk = sklearn_PCA(n_components=k)
    Z_sk = pca_sk.fit_transform(X)
    var_sk = pca_sk.explained_variance_ratio_
    
    # 3. Check explained variance (should match exactly)
    assert np.allclose(var_hand, var_sk), f"Variance mismatch: {var_hand} vs {var_sk}"
    
    # 4. Check projection (should match up to sign, as eigenvectors are only defined up to sign)
    for col in range(k):
        # Check if the absolute projection matches
        diff_same = np.allclose(Z_hand[:, col], Z_sk[:, col], atol=1e-5)
        diff_negated = np.allclose(Z_hand[:, col], -Z_sk[:, col], atol=1e-5)
        assert diff_same or diff_negated, f"Projection mismatch in column {col}"
        
    print("PCA SVD verification test: PASSED (matches scikit-learn perfectly)")

if __name__ == "__main__":
    test_pca_against_sklearn()
