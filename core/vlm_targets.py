"""vlm_targets.py - Multimodal target interface for Vision-Language Models (VLMs) via Ollama.
Allows sending both text prompts and images to local models like LLaVA and Moondream.
"""
import os
import base64
from core.targets import Target

class VLMTarget(Target):
    def __init__(self, name, model, base_url="http://localhost:11434/v1", api_key="ollama"):
        super().__init__(name, model, base_url, api_key)

    def generate_with_image(self, system, prompt, image_path, temperature=0.0, max_tokens=512):
        """
        Generates a response from the VLM target given a text prompt and an image.
        
        Args:
            system: System prompt string.
            prompt: User text prompt.
            image_path: Path to the image file to be embedded.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens to generate.
            
        Returns:
            str: Generated text response.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found at path: {image_path}")
            
        try:
            with open(image_path, "rb") as image_file:
                encoded_image = base64.b64encode(image_file.read()).decode("utf-8")
            image_data_url = f"data:image/jpeg;base64,{encoded_image}"
        except Exception as e:
            raise IOError(f"Failed to read/encode image at {image_path}: {e}")

        # Construct OpenAI-compatible multimodal message content
        content = [
            {"type": "text", "text": prompt},
            {
                "type": "image_url",
                "image_url": {
                    "url": image_data_url
                }
            }
        ]

        messages = [{"role": "user", "content": content}]
        return self.generate(system, messages, temperature=temperature, max_tokens=max_tokens)

def ollama_vlm_target(model):
    """Local vision model served by Ollama."""
    return VLMTarget(model, model, base_url="http://localhost:11434/v1", api_key="ollama")
