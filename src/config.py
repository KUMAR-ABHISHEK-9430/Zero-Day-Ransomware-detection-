import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Set


@dataclass
class PathsConfig:
    ROOT_DIR: Path = Path(__file__).parent.parent
    RAW_DATA_DIR: Path = ROOT_DIR / "data" / "raw_telemetry"
    PROCESSED_DATA_DIR: Path = ROOT_DIR / "data" / "processed"
    CHECKPOINT_DIR: Path = ROOT_DIR / "checkpoints"
    
    PEACETIME_LOG: Path = RAW_DATA_DIR / "system_telemetry.jsonl"
    ADVERSARIAL_LOG: Path = RAW_DATA_DIR / "simulated_attack_telemetry.jsonl"
    BEST_MODEL_PATH: Path = CHECKPOINT_DIR / "best_model.pt"

    def __post_init__(self):
        self.PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

@dataclass
class FeatureConfig:
    WINDOW_SIZE: int = 30        # Sequence length (W)
    STRIDE: int = 5              # Event slide interval (S)
    FEATURE_DIM: int = 10        # Features per event (F)
    TTL_SECONDS: int = 300       # Stale process buffer eviction (5 mins)
    CLEANUP_INTERVAL: int = 1000 # Events between TTL sweeps

    SCRIPT_HOSTS: Set[str] = field(default_factory=lambda: {
        'cmd.exe', 'powershell.exe', 'wscript.exe', 
        'cscript.exe', 'python.exe', 'bash.exe', 'mshta.exe'
    })
    
    USER_DATA_DIRS: Set[str] = field(default_factory=lambda: {
        '\\documents\\', '\\desktop\\', '\\pictures\\', 
        '\\downloads\\', '\\videos\\', '\\music\\'
    })



@dataclass
class ModelConfig:
    INPUT_DIM: int = 10
    SEQ_LEN: int = 30
    HIDDEN_DIM: int = 64
    LATENT_DIM: int = 32
    NUM_LAYERS: int = 2
    DROPOUT: float = 0.1




@dataclass
class TrainConfig:
    BATCH_SIZE: int = 128
    EPOCHS: int = 30
    LEARNING_RATE: float = 1e-3
    WEIGHT_DECAY: float = 1e-4
    TRAIN_SPLIT: float = 0.8
    PATIENCE: int = 5
    NUM_WORKERS: int = 2
    SEED: int = 42

    

class Config:
    paths = PathsConfig()
    features = FeatureConfig()
    model = ModelConfig()
    train = TrainConfig()

# Global config instance
cfg = Config()