from torch import nn

class CyberAttackLSTM(nn.Module):
    def __init__(self, input_features, hidden_features=16):
        super().__init__()
        self.lstm = nn.LSTM(input_size=input_features, hidden_size=hidden_features, batch_first=True)

        self.classifier = nn.Linear(hidden_features, 1)

    def forward(self, event_sequences):
        sequence_outputs, _ = self.lstm(event_sequences)

        final_event_output = sequence_outputs[:, -1, :]

        attack_logits = self.classifier(final_event_output)

        return attack_logits.squeeze(-1)