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