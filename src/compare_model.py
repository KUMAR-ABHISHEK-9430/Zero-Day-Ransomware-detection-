import os
import time
import torch
import torch.nn as nn
import numpy as np

from dataset import create_dataloaders, ShardedTelemetryDataset
from model import LSTMAutoencoder, CNNAutoencoder

DATA_DIR = "../data/processed"
BATCH_SIZE = 128
EPOCHS = 15
LEARNING_RATE = 1e-3

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def measure_inference_latency(model, sample_input, runs=1000):
    """Measures single-sample CPU/GPU forward pass latency in milliseconds."""
    model.eval()
    
    # Warmup
    with torch.no_grad():
        for _ in range(50):
            _ = model(sample_input)

    start = time.perf_counter()
    with torch.no_grad():
        for _ in range(runs):
            _ = model(sample_input)
    end = time.perf_counter()

    avg_latency_ms = ((end - start) / runs) * 1000.0
    return avg_latency_ms


def train_and_eval_model(model_name, model, train_loader, val_loader):
    print(f"\n==================================================")
    print(f"   BENCHMARKING MODEL: {model_name}")
    print(f"==================================================")
    
    model.to(device)
    criterion = nn.MSELoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
    use_amp = (device.type == "cuda")
    scaler = torch.amp.GradScaler(device.type, enabled=use_amp)

    # 1. Measure Training Execution Speed
    train_start = time.time()
    for epoch in range(1, EPOCHS + 1):
        model.train()
        running_loss = 0.0

        for batch_x in train_loader:
            batch_x = batch_x.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)

            with torch.amp.autocast(device.type, enabled=use_amp):
                recon = model(batch_x)
                loss = criterion(recon, batch_x)

            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            running_loss += loss.item() * batch_x.size(0)

    total_train_time = time.time() - train_start

    # 2. Evaluate Peacetime MSE & Threshold (99th Percentile)
    model.eval()
    val_errors = []
    with torch.no_grad():
        for batch_x in val_loader:
            batch_x = batch_x.to(device)
            recon = model(batch_x)
            sample_mse = torch.mean((batch_x - recon) ** 2, dim=(1, 2))
            val_errors.extend(sample_mse.cpu().numpy())

    val_errors = np.array(val_errors)
    mean_val_mse = np.mean(val_errors)
    theta_99 = np.percentile(val_errors, 99)

    # 3. Measure Single-Sample Inference Latency (Batch Size = 1)
    dummy_input = torch.randn(1, 30, 10).to(device)
    latency_ms = measure_inference_latency(model, dummy_input)

    # 4. Measure Adversarial Detection (if dataset exists)
    tpr = 0.0
    try:
        adv_dataset = ShardedTelemetryDataset(data_dir=DATA_DIR, prefix="X_simulated_attack")
        adv_loader = torch.utils.data.DataLoader(adv_dataset, batch_size=BATCH_SIZE, shuffle=False)
        adv_errors = []
        with torch.no_grad():
            for batch_x in adv_loader:
                batch_x = batch_x.to(device)
                recon = model(batch_x)
                sample_mse = torch.mean((batch_x - recon) ** 2, dim=(1, 2))
                adv_errors.extend(sample_mse.cpu().numpy())

        adv_errors = np.array(adv_errors)
        detections = np.sum(adv_errors > theta_99)
        tpr = (detections / len(adv_errors)) * 100.0
    except FileNotFoundError:
        pass

    # Parameter Count
    total_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    return {
        "Name": model_name,
        "Parameters": total_params,
        "Train Time (s)": total_train_time,
        "Single-Sample Latency (ms)": latency_ms,
        "Peacetime Mean MSE": mean_val_mse,
        "Threshold (theta_99)": theta_99,
        "Adversarial TPR (%)": tpr
    }


def run_comparison():
    train_loader, val_loader = create_dataloaders(data_dir=DATA_DIR, batch_size=BATCH_SIZE)

    lstm_model = LSTMAutoencoder(input_dim=10, seq_len=30, hidden_dim=64, latent_dim=32, num_layers=2)
    cnn_model = CNNAutoencoder(input_dim=10, seq_len=30, latent_dim=32)

    results = []
    results.append(train_and_eval_model("LSTM Autoencoder", lstm_model, train_loader, val_loader))
    results.append(train_and_eval_model("1D-CNN Autoencoder", cnn_model, train_loader, val_loader))

    print("\n\n==================================================")
    print("           EMPIRICAL COMPARISON SUMMARY           ")
    print("==================================================")
    print(f"{'Metric':<30} | {'LSTM Autoencoder':<18} | {'1D-CNN Autoencoder':<18}")
    print("-" * 72)
    
    r_lstm, r_cnn = results[0], results[1]
    for key in r_lstm.keys():
        if key == "Name":
            continue
        val1 = f"{r_lstm[key]:.4f}" if isinstance(r_lstm[key], float) else f"{r_lstm[key]:,}"
        val2 = f"{r_cnn[key]:.4f}" if isinstance(r_cnn[key], float) else f"{r_cnn[key]:,}"
        print(f"{key:<30} | {val1:<18} | {val2:<18}")

if __name__ == "__main__":
    run_comparison()