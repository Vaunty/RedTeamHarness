"""embed.py - Text to vector embeddings using sentence-transformers.
Uses the lightweight 384-dimensional all-MiniLM-L6-v2 model which runs quickly on CPU.
"""
import numpy as np

_model = None

def get_model():
    """Lazy loader for the SentenceTransformer model to avoid load-time overhead."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model

def embed(texts):
    """
    Embeds a string or a list of strings into normalized 384-dimensional vectors.
    L2 normalization ensures that the dot product is equivalent to cosine similarity.
    
    Args:
        texts: A string or list of strings.
        
    Returns:
        A numpy array of shape (384,) for a single string, or (n, 384) for a list of strings.
    """
    model = get_model()
    is_single = isinstance(texts, str)
    if is_single:
        texts = [texts]
        
    embeddings = model.encode(list(texts), normalize_embeddings=True)
    embeddings = np.asarray(embeddings, dtype=np.float32)
    
    if is_single:
        return embeddings[0]
    return embeddings
