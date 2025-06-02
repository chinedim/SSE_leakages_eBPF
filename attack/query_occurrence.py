import os, re
from collections import Counter, defaultdict

PLAINTEXT_DIR = "searchable-encryption-database/data_owner/plaintexts/sample100"  # adjust if different


# Generating query counts for preliminary knowledge about the datasets
def generate_query_counts():
# Path to the plaintext Enron emails (if available)

    word_freq = Counter()

    for filename in os.listdir(PLAINTEXT_DIR):
        text = open(os.path.join(PLAINTEXT_DIR, filename), 'r', errors='ignore').read().lower()
        words = re.findall(r"\w+", text)  # basic tokenization on alphanumeric words
        unique_words = set(words)
        for w in unique_words:
            word_freq[w] += 1

    # Example: print some frequencies
    with open ("attack/query_occurrence.txt", "w") as file:
        for word, freq in list(word_freq.items()):
            if freq >= 4: 
                file.write(f"{word}: {freq}\n")
    
    return word_freq

def generate_word_docs():
    word_docs = defaultdict(set)
    for filename in os.listdir(PLAINTEXT_DIR):
        text = open(os.path.join(PLAINTEXT_DIR, filename), 'r', errors='ignore').read().lower()
        words = re.findall(r"\w+", text)
        unique_words = set(words)
        for w in unique_words:
            word_docs[w].add(filename)
    return word_docs

def get_search_terms():
    # Actual search terms done in an attack
    search_terms = ["services", "complete", "information", "lavorato", "phone", "send", "message", "manager", "mail", "project", "will", "mark", "today", "gas", "martin", "password", "into", "good"]  # list your keywords
    return search_terms

def get_observations(ebpf= False):
    # Observed token data (collected from Phase 2)
    observations = [("T1", 5), ("T2", 12), ("T3", 6), ("T4", 6), ("T5", 13),("T6", 11),("T7", 4),("T8", 7),("T9", 16),("T10", 15), ("T11", 39),("T12", 12),("T13", 12),("T14", 22),("T15", 8), ("T16", 4), ("T17", 12), ("T18", 12)] 
    
    observations_ebpf = [("T1", 5, {"email_00010_phillip.allen_to_buck.buckner.txt", "email_00047_phillip.allen_to_stagecoachmama.txt", "email_00059_phillip.allen_to_ina.rangel.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt"}), 
                         ("T2", 12, {"email_00023_phillip.allen_to_lkuch.txt", "email_00024_phillip.allen_to_jeffrey.hodge.txt", "email_00028_phillip.allen_to_rlehmann.txt", "email_00032_phillip.allen_to_jsmith.txt", "email_00040_phillip.allen_to_cbpres.txt", "email_00041_phillip.allen_to_pallen70.txt", "email_00051_phillip.allen_to_keith.holst.txt", "email_00057_phillip.allen_to_pallen70.txt", "email_00059_phillip.allen_to_ina.rangel.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt", "email_00091_phillip.allen_to_stagecoachmama.txt"}), 
                         ("T3", 6, {"email_00018_phillip.allen_to_pallen70.txt", "email_00037_phillip.allen_to_kathy.moore.txt", "email_00058_phillip.allen_to_pallen70.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt", "email_00071_phillip.allen_to_ina.rangel.txt"}), 
                         ("T4", 6, {"email_00006_phillip.allen_to_david.l.johnson.txt", "email_00059_phillip.allen_to_ina.rangel.txt", "email_00063_phillip.allen_to_ina.rangel.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt", "email_00072_phillip.allen_to_debe.txt"}), 
                         ("T5", 13, set()),
                         ("T6", 11, set()),
                         ("T7", 4, {"email_00061_phillip.allen_to_ina.rangel.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt", "email_00074_phillip.allen_to_muller.txt"}),
                         ("T8", 7, set()),
                         ("T9", 16, set()),
                         ("T10", 15, set()), 
                         ("T11", 39, set()),
                         ("T12", 10, set()),
                         ("T13", 12, {"email_00018_phillip.allen_to_pallen70.txt", "email_00032_phillip.allen_to_jsmith.txt", "email_00037_phillip.allen_to_kathy.moore.txt", "email_00041_phillip.allen_to_pallen70.txt", "email_00051_phillip.allen_to_keith.holst.txt", "email_00056_phillip.allen_to_pallen70.txt", "email_00057_phillip.allen_to_pallen70.txt", "email_00077_phillip.allen_to_mark.txt", "email_00087_phillip.allen_to_stagecoachmama.txt", "email_00094_phillip.allen_to_pallen70.txt", "email_00095_phillip.allen_to_pallen70.txt", "email_00096_phillip.allen_to_pallen70.txt"}),
                         ("T14", 22, set()),
                         ("T15", 8, set()), 
                         ("T16", 4, {"email_00017_phillip.allen_to_tim.heizenrader.txt", "email_00037_phillip.allen_to_kathy.moore.txt", "email_00061_phillip.allen_to_ina.rangel.txt", "email_00079_phillip.allen_to_mark.txt"}), 
                         ("T17", 12, {"email_00012_phillip.allen_to_keith.holst.txt", "email_00013_phillip.allen_to_keith.holst.txt", "email_00023_phillip.allen_to_lkuch.txt", "email_00024_phillip.allen_to_jeffrey.hodge.txt", "email_00025_phillip.allen_to_kholst.txt", "email_00026_phillip.allen_to_pallen70.txt", "email_00041_phillip.allen_to_pallen70.txt", "email_00051_phillip.allen_to_keith.holst.txt", "email_00057_phillip.allen_to_pallen70.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt", "email_00097_phillip.allen_to_mac.d.hargrove.txt"}), 
                         ("T18", 12, {"email_00012_phillip.allen_to_keith.holst.txt", "email_00013_phillip.allen_to_keith.holst.txt", "email_00021_phillip.allen_to_stouchstone.txt", "email_00025_phillip.allen_to_kholst.txt", "email_00026_phillip.allen_to_pallen70.txt", "email_00033_phillip.allen_to_christopher.calger.txt", "email_00041_phillip.allen_to_pallen70.txt", "email_00051_phillip.allen_to_keith.holst.txt", "email_00057_phillip.allen_to_pallen70.txt", "email_00065_phillip.allen_to_ina.rangel.txt", "email_00070_phillip.allen_to_ina.rangel.txt", "email_00074_phillip.allen_to_muller.txt"})] 
    if ebpf:
        return observations_ebpf
    else:
        return observations

def query_recovery_ebpf(word_freq, search_terms, observations, word_docs):
        # Known frequency distribution for queried keywords (from word_freq computed earlier)
        # For example, if we queried the words in search_terms, filter those:
        queried_freq = {w: word_freq[w] for w in sorted(search_terms)} 

        # Sort tokens by observed count, and words by frequency
        observations.sort(key=lambda x: x[1])  # sort by count
        sorted_words = sorted(queried_freq.items(), key=lambda x: x[1])  # list of (word, freq) sorted by freq

        mapping_guess = {}   # token -> guessed keyword
        used_words = set()    # to keep track of assigned words

        # Iterate through tokens and assign the closest frequency match
        for (token, count, doc_set) in observations:
            # Find all candidate words with this frequency
            match = None
            candidates = [word for word, freq in sorted_words if freq == count and word not in used_words]
            if len(candidates) == 1:
                match = candidates[0]           
            elif len(candidates) > 1:
                # We use the word docs and files opend gotten from observing with eBPF
                for w in candidates:
                # only compare among your candidates
                    if word_docs.get(w) == doc_set:
                        match = w
                        break

            mapping_guess[token] = match
            if match is not None:
                used_words.add(match)
                
                

        # Print the guessed mapping
        for token, guess in mapping_guess.items():
            print(f"{token} -> {guess}")
        return mapping_guess

def query_recovery(word_freq, search_terms, observations):
        # Known frequency distribution for queried keywords (from word_freq computed earlier)
        # For example, if we queried the words in search_terms, filter those:
        queried_freq = {w: word_freq[w] for w in sorted(search_terms)}

        

        # Sort tokens by observed count, and words by frequency
        observations.sort(key=lambda x: x[1])  # sort by count
        sorted_words = sorted(queried_freq.items(), key=lambda x: x[1])  # list of (word, freq) sorted by freq

        mapping_guess = {}   # token -> guessed keyword
        used_words = set()    # to keep track of assigned words

        # Iterate through tokens and assign the closest frequency match
        for (token, count) in observations:
            # Find all candidate words with this frequency
            candidates = [word for word, freq in sorted_words if freq == count and word not in used_words]
            if len(candidates) == 1:
                mapping_guess[token] = candidates[0]
                used_words.add(candidates[0])
            elif len(candidates) > 1:
                # Ambiguity: multiple words have the same frequency.
                # We guess one (pick the first) – this may be wrong if it’s not actually that one.
                guessed_word = candidates[0]
                mapping_guess[token] = guessed_word
                used_words.add(guessed_word)
                # (In a real attack, attacker might not be able to resolve this tie without more info.)
            else:
                # No direct candidate (this might happen if distribution knowledge is incomplete or query not in dataset)
                mapping_guess[token] = None
                

        # Print the guessed mapping
        for token, guess in mapping_guess.items():
            print(f"{token} -> {guess}")
        return mapping_guess

def get_true_mapping(search_terms, observations):
    true_mapping= {}
    for index, count in observations:
        i = int(index[1:])
        true_mapping[index] = search_terms[i-1]
        print(f"{index} -> {search_terms[i-1]}")
    return true_mapping


def get_accuracy(mapping_guess, true_mapping):
    # Evaluate accuracy
    total = len(true_mapping)
    correct = sum(1 for token, true_word in true_mapping.items() 
                if token in mapping_guess and mapping_guess[token] == true_word)
    accuracy = correct / total
    print(f"Baseline FMA Accuracy: {accuracy*100:.1f}% ({correct} of {total} queries correctly identified)")

def plot_accuracy():
    pass

def main():
    word_freq = generate_query_counts()
    search_terms = get_search_terms()
    observations = get_observations()
    
    print("---------------Actual Keywords---------------")
    true_mapping= get_true_mapping(search_terms, observations)

    print("---------------Frequency Attack without eBPF---------------")
    # print("---------------Guessed Keywords---------------")
    
    mapping_guess = query_recovery(word_freq, search_terms, observations)
    accuracy =get_accuracy(mapping_guess, true_mapping)


    print("/n---------------Frequesnce Attack with eBPF---------------")
    observations = get_observations(ebpf=True)
    word_docs = generate_word_docs()
    mapping_guess_ebpf = query_recovery_ebpf(word_freq, search_terms, observations,word_docs)
    accuracy =get_accuracy(mapping_guess_ebpf, true_mapping)


if __name__ == '__main__':
    main()