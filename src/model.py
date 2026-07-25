import torch
import torch.nn as nn

class LSTMAutoencoder(nn.Module):
    """
    Recurrent Autoencoder for multi-feature sequence reconstruction.
    Input Shape:  [batch_size, seq_len=30, input_dim=10]
    Output Shape: [batch_size, seq_len=30, input_dim=10]
    """
    def __init__(self, input_dim=10, seq_len=30, hidden_dim=64, latent_dim=32, num_layers=2):
        super().__init__()
        self.seq_len = seq_len
        self.input_dim = input_dim

        # Encoder Network
        self.encoder_lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1 if num_layers > 1 else 0.0
        )
        self.encoder_fc = nn.Linear(hidden_dim, latent_dim)

        # Decoder Network
        self.decoder_fc = nn.Linear(latent_dim, hidden_dim)
        self.decoder_lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.1 if num_layers > 1 else 0.0
        )
        self.output_layer = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        # x: [batch_size, 30, 10]
        
        # 1. Encode
        _, (hn, _) = self.encoder_lstm(x)           # hn: [num_layers, batch_size, hidden_dim]
        latent = self.encoder_fc(hn[-1])             # latent: [batch_size, latent_dim]

        # 2. Decode Sequence
        dec_hidden = self.decoder_fc(latent)         # dec_hidden: [batch_size, hidden_dim]
        dec_input = dec_hidden.unsqueeze(1).repeat(1, self.seq_len, 1) # [batch_size, 30, hidden_dim]

        dec_output, _ = self.decoder_lstm(dec_input) # dec_output: [batch_size, 30, hidden_dim]
        reconstructed = self.output_layer(dec_output) # [batch_size, 30, 10]

        return reconstructed




class CNNAutoencoder(nn.Module):
    """
    1D Convolutional Autoencoder for temporal feature extraction.
    Input Shape:  [batch_size, seq_len=30, input_dim=10]
    Output Shape: [batch_size, seq_len=30, input_dim=10]
    """
    def __init__(self, input_dim=10, seq_len=30, latent_dim=32):
        super().__init__()
        self.input_dim = input_dim
        self.seq_len = seq_len

        # Encoder: [B, 10, 30] -> [B, 32, 30] -> [B, 64, 15] -> [B, 128, 8]
        self.encoder_conv = nn.Sequential(
            nn.Conv1d(in_channels=input_dim, out_channels=32, kernel_size=3, stride=1, padding=1),
            nn.BatchNorm1d(32),
            nn.GELU(),
            
            nn.Conv1d(in_channels=32, out_channels=64, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(64),
            nn.GELU(),
            
            nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(128),
            nn.GELU()
        )
        
        # Latent Space Projections (128 channels * 8 length = 1024 flat features)
        self.flat_dim = 128 * 8
        self.encoder_fc = nn.Linear(self.flat_dim, latent_dim)
        self.decoder_fc = nn.Linear(latent_dim, self.flat_dim)

        # Decoder: [B, 128, 8] -> [B, 64, 15] -> [B, 32, 30] -> [B, 10, 30]
        self.decoder_conv = nn.Sequential(
            nn.ConvTranspose1d(in_channels=128, out_channels=64, kernel_size=3, stride=2, padding=1, output_padding=0),
            nn.BatchNorm1d(64),
            nn.GELU(),
            
            nn.ConvTranspose1d(in_channels=64, out_channels=32, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm1d(32),
            nn.GELU(),
            
            nn.Conv1d(in_channels=32, out_channels=input_dim, kernel_size=3, stride=1, padding=1)
        )

    def forward(self, x):
        # x shape: [B, 30, 10]
        # Permute to PyTorch Conv1d format: [B, Channels=10, Seq_Len=30]
        x_perm = x.permute(0, 2, 1)

        # 1. Encode
        conv_out = self.encoder_conv(x_perm)                 # [B, 128, 8]
        flat = conv_out.view(conv_out.size(0), -1)           # [B, 1024]
        latent = self.encoder_fc(flat)                       # [B, latent_dim]

        # 2. Decode
        dec_flat = self.decoder_fc(latent)                   # [B, 1024]
        dec_unflat = dec_flat.view(dec_flat.size(0), 128, 8) # [B, 128, 8]
        recon_conv = self.decoder_conv(dec_unflat)           # [B, 10, 30]

        # Permute back to standard format: [B, 30, 10]
        reconstructed = recon_conv.permute(0, 2, 1)
        return reconstructed