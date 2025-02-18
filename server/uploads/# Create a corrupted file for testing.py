# Create a corrupted file for testing
original_file = "text1.txt"
corrupted_file = "corrupted_sample.txt"

with open(original_file, "rb") as f:
    data = f.read()

# Corrupt the data by altering some bytes
corrupted_data = bytearray(data)
for i in range(0, len(corrupted_data), 50):  # Corrupt every 50th byte
    corrupted_data[i] = corrupted_data[i] ^ 0xFF  # XOR to flip bits

with open(corrupted_file, "wb") as f:
    f.write(corrupted_data)

print(f"Corrupted file created: {corrupted_file}")
