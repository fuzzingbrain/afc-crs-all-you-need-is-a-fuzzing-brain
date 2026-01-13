"""
LLM Distributor

Tier-based model selection system for routing requests to appropriate model tiers.
Supports automatic routing based on TaskType and manual tier selection.
"""

from enum import Enum
from typing import Dict, List, Optional

from .models import (
    ModelInfo,
    Provider,
    TaskType,
    # T1 Models (Reasoning)
    O3,
    CLAUDE_OPUS_4_5,
    GPT_5_2_PRO,
    # T2 Models (Main)
    GPT_5_2_CODEX,
    CLAUDE_SONNET_4_5,
    GEMINI_3_PRO,
    # T3 Models (Utils)
    GPT_5_MINI,
    CLAUDE_HAIKU_4_5,
    GEMINI_3_FLASH,
)


class ModelTier(Enum):
    """Model tier classification"""
    T1 = "T1"  # Reasoning - Most capable models
    T2 = "T2"  # Main - Balanced models for general use
    T3 = "T3"  # Utils - Fast, cost-effective models


# Tier model mappings (prefer latest versions)
TIER_MODELS: Dict[ModelTier, List[ModelInfo]] = {
    ModelTier.T1: [
        O3,
        CLAUDE_OPUS_4_5,
        GPT_5_2_PRO,
    ],
    ModelTier.T2: [
        GPT_5_2_CODEX,
        CLAUDE_SONNET_4_5,
        GEMINI_3_PRO,
    ],
    ModelTier.T3: [
        GPT_5_MINI,
        CLAUDE_HAIKU_4_5,
        GEMINI_3_FLASH,
    ],
}

# TaskType to Tier routing rules
TASK_TO_TIER: Dict[TaskType, ModelTier] = {
    TaskType.COMPLEX_REASONING: ModelTier.T1,
    TaskType.CODE_ANALYSIS: ModelTier.T2,
    TaskType.CODE_REFACTOR: ModelTier.T2,
    TaskType.FAST_CODING: ModelTier.T3,
    TaskType.FAST_JUDGMENT: ModelTier.T3,
    TaskType.GENERAL: ModelTier.T2,
}


class LLMDistributor:
    """
    LLM Distributor for tier-based model selection.
    
    Routes requests to appropriate model tiers (T1/T2/T3) based on task type
    or allows manual tier selection.
    
    Usage:
        # Get singleton instance
        distributor = LLMDistributor.get_instance()
        
        # Or create a new instance
        distributor = LLMDistributor()
        
        # Automatic routing based on task type
        model = distributor.get_model_for_task(TaskType.COMPLEX_REASONING)
        
        # Manual tier selection
        model = distributor.get_model_for_tier(ModelTier.T1)
        
        # Get all models in a tier
        models = distributor.get_models_for_tier(ModelTier.T2)
    """
    
    # Class variable for singleton instance
    _instance: Optional['LLMDistributor'] = None
    
    @classmethod
    def get_instance(cls) -> 'LLMDistributor':
        """
        Get the singleton distributor instance.
        
        Returns:
            The default LLMDistributor instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def get_models_for_tier(self, tier: ModelTier) -> List[ModelInfo]:
        """
        Get all models in the specified tier.
        
        Args:
            tier: Model tier (T1, T2, or T3)
            
        Returns:
            List of ModelInfo objects in the tier
        """
        return TIER_MODELS.get(tier, [])
    
    def get_model_for_tier(
        self,
        tier: ModelTier,
        preferred_provider: Optional[Provider] = None,
    ) -> ModelInfo:
        """
        Get a model from the specified tier.
        
        Args:
            tier: Model tier (T1, T2, or T3)
            preferred_provider: Optional provider preference (filters models by provider)
            
        Returns:
            ModelInfo for the selected model (first available in tier)
        """
        models = TIER_MODELS.get(tier, [])
        
        if not models:
            # Fallback to T2 if tier is empty
            models = TIER_MODELS.get(ModelTier.T2, [])
        
        # Filter by provider preference if specified
        if preferred_provider:
            filtered_models = [m for m in models if m.provider == preferred_provider]
            if filtered_models:
                return filtered_models[0]
        
        # Return first model in tier
        return models[0] if models else CLAUDE_SONNET_4_5  # Ultimate fallback
    
    def get_model_for_task(
        self,
        task_type: TaskType,
        preferred_tier: Optional[ModelTier] = None,
        preferred_provider: Optional[Provider] = None,
    ) -> ModelInfo:
        """
        Get a model for a specific task type using automatic routing.
        
        Args:
            task_type: Type of task to route
            preferred_tier: Optional tier override (bypasses automatic routing)
            preferred_provider: Optional provider preference
            
        Returns:
            ModelInfo for the selected model
        """
        # Use preferred tier if specified, otherwise route based on task type
        tier = preferred_tier if preferred_tier is not None else TASK_TO_TIER.get(
            task_type, ModelTier.T2  # Default to T2
        )
        
        return self.get_model_for_tier(tier, preferred_provider)


# Convenience function for backward compatibility
def get_distributor() -> LLMDistributor:
    """
    Get the default distributor instance (convenience function).
    
    This is a wrapper around LLMDistributor.get_instance() for backward compatibility.
    
    Returns:
        The default LLMDistributor instance
    """
    return LLMDistributor.get_instance()
