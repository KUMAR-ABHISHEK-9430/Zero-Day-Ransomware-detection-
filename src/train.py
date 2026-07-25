import os
import time
import torch
import torch.nn as nn

from pathlib import Path
import numpy as np

from dataset import create_dataloaders, ShardedTelemetryDataset
from model import LSTMAutoencoder

# =====================================================================
# CONFIGURATION
# =====================================================================
DATA_DIR = "./data/processed"
CHECKPOINT_DIR = "./checkpoints"
BATCH_SIZE = 128
EPOCHS = 30
LEARNING_RATE = 1e-3
PATIENCE = 5  # Early stopping patience

# Select acceleration backend
device_type = "cuda" if torch.cuda.is_available() else "cpu"
device = torch.device(device_type)


def train_model():
    print(f"[*] Starting execution on device: {device}")
    Path(CHECKPOINT_DIR).mkdir(parents=True, exist_ok=True)

    # 1. Prepare Data
    train_loader, val_loader = create_dataloaders(
        data_dir=DATA_DIR,
        batch_size=BATCH_SIZE,
        train_split=0.8
    )

    # 2. Instantiate Model
    raw_model = LSTMAutoencoder(input_dim=10, seq_len=30, hidden_dim=64, latent_dim=32, num_layers=2)
    raw_model.to(device)

    # Apply PyTorch 2.0 Graph Compilation for acceleration
    try:
        model = torch.compile(raw_model)
        print("[*] Successfully compiled model via torch.compile()")
    except Exception as e:
        print(f"[!] torch.compile skipped: {e}")
        model = raw_model

    criterion = nn.MSELoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)

    # Initialize PyTorch AMP Scaler
    use_amp = (device_type == "cuda")
    scaler = torch.amp.GradScaler(device_type, enabled=use_amp)

    best_val_loss = float('inf')
    patience_counter = 0
    best_checkpoint_path = os.path.join(CHECKPOINT_DIR, "best_model.pt")

    # 3. Training Loop
    print("\n--- Starting Training Loop ---")
    for epoch in range(1, EPOCHS + 1):
        start_time = time.time()
        
        # Training Phase
        model.train()
        running_train_loss = 0.0

        for batch_x in train_loader:
            batch_x = batch_x.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)

            # AMP Autocast Context
            with torch.amp.autocast(device_type, enabled=use_amp):
                reconstructed = model(batch_x)
                loss = criterion(reconstructed, batch_x)

            # Scaled Backward Pass
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            running_train_loss += loss.item() * batch_x.size(0)

        epoch_train_loss = running_train_loss / len(train_loader.dataset)

        # Validation Phase
        model.eval()
        running_val_loss = 0.0

        with torch.no_grad():
            for batch_x in val_loader:
                batch_x = batch_x.to(device, non_blocking=True)
                with torch.amp.autocast(device_type, enabled=use_amp):
                    reconstructed = model(batch_x)
                    loss = criterion(reconstructed, batch_x)
                running_val_loss += loss.item() * batch_x.size(0)

        epoch_val_loss = running_val_loss / len(val_loader.dataset)
        scheduler.step(epoch_val_loss)

        elapsed = time.time() - start_time
        print(f"Epoch {epoch:02d}/{EPOCHS:02d} | Train MSE: {epoch_train_loss:.6f} | Val MSE: {epoch_val_loss:.6f} | Time: {elapsed:.2f}s")

        # Checkpointing Strategy
        if epoch_val_loss < best_val_loss:
            best_val_loss = epoch_val_loss
            patience_counter = 0

            checkpoint = {
                'epoch': epoch,
                'model_state_dict': raw_model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_loss': best_val_loss,
                'config': {'input_dim': 10, 'seq_len': 30, 'hidden_dim': 64, 'latent_dim': 32}
            }
            torch.save(checkpoint, best_checkpoint_path)
            print(f"  └── Checkpoint saved: {best_checkpoint_path}")
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"[!] Early stopping triggered at epoch {epoch}.")
                break

    # 4. Threshold Calibration Phase
    print("\n--- Calibrating Decision Threshold (theta) ---")
    calibrate_threshold(raw_model, best_checkpoint_path, val_loader)

    # 5. Adversarial Check Phase
    evaluate_adversarial(raw_model, best_checkpoint_path)


def calibrate_threshold(raw_model, checkpoint_path, val_loader):
    """Computes the 99th percentile reconstruction loss on peacetime validation data."""
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    raw_model.load_state_dict(checkpoint['model_state_dict'])
    raw_model.eval()

    val_errors = []

    with torch.no_grad():
        for batch_x in val_loader:
            batch_x = batch_x.to(device)
            reconstructed = raw_model(batch_x)
            
            # Compute per-sample MSE across matrix: shape [batch_size]
            sample_mse = torch.mean((batch_x - reconstructed) ** 2, dim=(1, 2))
            val_errors.extend(sample_mse.cpu().numpy())

    val_errors = np.array(val_errors)
    theta_99 = np.percentile(val_errors, 99)
    theta_mean_std = np.mean(val_errors) + (3 * np.std(val_errors))

    selected_theta = float(theta_99)

    print(f"[+] Peacetime MSE Mean: {np.mean(val_errors):.6f} | Std: {np.std(val_errors):.6f}")
    print(f"[+] Calibrated Anomaly Threshold (99th Percentile): theta = {selected_theta:.6f}")

    # Append threshold into model checkpoint file
    checkpoint['threshold'] = selected_theta
    torch.save(checkpoint, checkpoint_path)
    print(f"[+] Updated checkpoint with theta = {selected_theta:.6f}")


def evaluate_adversarial(raw_model, checkpoint_path):
    """Evaluates the model against adversarial attack shards (label = 1) if present."""
    try:
        adv_dataset = ShardedTelemetryDataset(data_dir=DATA_DIR, prefix="X_simulated_attack")
    except FileNotFoundError:
        print("[!] No adversarial shards found. Skipping adversarial evaluation phase.")
        return

    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    raw_model.load_state_dict(checkpoint['model_state_dict'])
    theta = checkpoint.get('threshold', 0.05)
    raw_model.eval()

    adv_loader = torch.utils.data.DataLoader(adv_dataset, batch_size=BATCH_SIZE, shuffle=False)
    adv_errors = []

    with torch.no_grad():
        for batch_x in adv_loader:
            batch_x = batch_x.to(device)
            reconstructed = raw_model(batch_x)
            sample_mse = torch.mean((batch_x - reconstructed) ** 2, dim=(1, 2))
            adv_errors.extend(sample_mse.cpu().numpy())

    adv_errors = np.array(adv_errors)
    detections = np.sum(adv_errors > theta)
    tpr = (detections / len(adv_errors)) * 100

    print(f"\n--- Adversarial Validation Summary ---")
    print(f"Total Attack Windows Evaluated : {len(adv_errors):,}")
    print(f"Mean Attack MSE Reconstruction : {np.mean(adv_errors):.6f}")
    print(f"True Positive Rate (TPR @ theta) : {tpr:.2f}% ({detections}/{len(adv_errors)} detected)")


if __name__ == "__main__":
    train_model()