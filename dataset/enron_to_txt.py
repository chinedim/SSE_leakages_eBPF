import pandas as pd
import os
import re

# Load the dataset
df = pd.read_csv('archive/emaildata_100000_0.csv', nrows=100)

# Directory to save the text files
output_dir = '../searchable-encryption-database/data_owner/plaintexts/sample100'
os.makedirs(output_dir, exist_ok=True)

# Helper function to sanitize filenames
def sanitize_filename(filename):
    filename = re.sub(r'[^\w\-_. ]', '_', filename)
    return filename

# Iterate through DataFrame and save each email subject and body as a text file
for index, row in df.iterrows():
    sender = row['sender'].split('@')[0] if pd.notnull(row['sender']) else 'unknown_sender'
    recipient = row['recipient1'].split('@')[0] if pd.notnull(row['recipient1']) else 'unknown_recipient'
    subject = row['subject'] if pd.notnull(row['subject']) else 'No Subject'
    body = row['text'] if pd.notnull(row['text']) else ''

    # Define the filename
    filename = f"email_{str(index).zfill(5)}_{sender}_to_{recipient}.txt"
    filename = sanitize_filename(filename)
    filepath = os.path.join(output_dir, filename)

    # Write the email subject and body to the text file
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(f"Subject: {subject}\n\n{body}")

print(f"Generated {len(df)} email text files in {output_dir}.")


