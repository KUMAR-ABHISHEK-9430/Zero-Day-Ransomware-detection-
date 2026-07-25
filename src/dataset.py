import os
import glob
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader

class ShardedTelemetryDataset(Dataset):
    """
    Memory-mapped PyTorch Dataset that lazily accesses binary .npy tensor shards
    without exhausting host RAM.
    """
    def __init__(self, data_dir, prefix="X_"):
        super().__init__()
        self.data_dir = data_dir
        
        # Search for matching binary shard paths
        search_pattern = os.path.join(data_dir, f"{prefix}*.npy")
        self.shard_paths = sorted(glob.glob(search_pattern))
        
        if not self.shard_paths:
            raise FileNotFoundError(f"No shard files matching '{prefix}*.npy' found in {data_dir}")

        self.mmaps = []
        self.cumulative_sizes = [0]
        total_samples = 0

        # Inspect headers of each shard via mmap
        for path in self.shard_paths:
            arr_mmap = np.load(path, mmap_mode='r')
            self.mmaps.append(arr_mmap)
            total_samples += arr_mmap.shape[0]
            self.cumulative_sizes.append(total_samples)

        self.total_samples = total_samples
        print(f"[*] Initialized ShardedTelemetryDataset: {len(self.shard_paths)} shards, {self.total_samples:,} total samples.")

    def __len__(self):
        return self.total_samples

    def __getitem__(self, idx):
        if idx < 0 or idx >= self.total_samples:
            raise IndexError(f"Index {idx} out of range for dataset of size {self.total_samples}")

        # Locate the specific shard via binary search
        shard_idx = np.searchsorted(self.cumulative_sizes, idx, side='right') - 1
        local_idx = idx - self.cumulative_sizes[shard_idx]

        # Extract 3D tensor slice [30, 10]
        sample = self.mmaps[shard_idx][local_idx]
        return torch.from_numpy(sample.copy()).float()


def create_dataloaders(data_dir, batch_size=64, train_split=0.8, num_workers=2):
    """Creates train and validation DataLoaders from peacetime telemetry shards."""
    full_dataset = ShardedTelemetryDataset(data_dir=data_dir, prefix="X_system_telemetry")
    
    total_len = len(full_dataset)
    train_size = int(total_len * train_split)
    val_size = total_len - train_size

    train_dataset, val_dataset = torch.utils.data.random_split(
        full_dataset, [train_size, val_size],
        generator=torch.Generator().manual_seed(42)
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=num_workers,
        pin_memory=True,
        drop_last=True
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=True
    )

    return train_loader, val_loader