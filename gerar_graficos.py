import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Carrega o CSV
df = pd.read_csv("resultados_tcc_frost_vs_ssh.csv")

# Calcula estatísticas descritivas
stats = df.groupby(["cenario", "abordagem"])["latencia_ms"].agg(
    media="mean",
    mediana="median",
    desvio_padrao="std",
    minimo="min",
    maximo="max"
).reset_index()

print("\n=== TABELA ESTATÍSTICA (ms) ===")
print(stats.to_string(index=False))
stats.to_csv("estatisticas_resumo_tcc.csv", index=False)

# Configuração visual 
plt.rcParams.update({"font.size": 11, "figure.dpi": 300})
cenarios_ordem = ["LAN_0ms", "WAN_50ms", "WAN_100ms"]
cenarios_labels = ["LAN (0 ms)", "WAN Regional (50 ms)", "WAN Intercontinental (100 ms)"]

frost_means = [stats[(stats["cenario"] == c) & (stats["abordagem"] == "FROST_2de3")]["media"].values[0] for c in cenarios_ordem]
frost_stds = [stats[(stats["cenario"] == c) & (stats["abordagem"] == "FROST_2de3")]["desvio_padrao"].values[0] for c in cenarios_ordem]

ssh_means = [stats[(stats["cenario"] == c) & (stats["abordagem"] == "SSH_Convencional")]["media"].values[0] for c in cenarios_ordem]
ssh_stds = [stats[(stats["cenario"] == c) & (stats["abordagem"] == "SSH_Convencional")]["desvio_padrao"].values[0] for c in cenarios_ordem]

# Gráfico 1: Barras agrupadas com barras de erro (Desvio Padrão)
x = np.arange(len(cenarios_labels))
width = 0.35

fig, ax = plt.subplots(figsize=(8, 5))
rects1 = ax.bar(x - width/2, frost_means, width, yerr=frost_stds, capsize=5, label="FROST 2-de-3 (mTLS)", color="#1f77b4", edgecolor="black")
rects2 = ax.bar(x + width/2, ssh_means, width, yerr=ssh_stds, capsize=5, label="SSH Convencional (Ed25519)", color="#ff7f0e", edgecolor="black")

ax.set_ylabel("Latência Média (ms)")
ax.set_title("Comparação de Latência: Assinatura FROST 2-de-3 vs. SSH Convencional (n=30)")
ax.set_xticks(x)
ax.set_xticklabels(cenarios_labels)
ax.legend()
ax.grid(axis="y", linestyle="--", alpha=0.6)

# Adiciona valores acima das barras
for rect in rects1:
    h = rect.get_height()
    ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 5),
                textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")
for rect in rects2:
    h = rect.get_height()
    ax.annotate(f"{h:.1f}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 5),
                textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")

plt.tight_layout()
plt.savefig("grafico_comparativo_latencia.png")
print("\nGráfico salvo: grafico_comparativo_latencia.png")
