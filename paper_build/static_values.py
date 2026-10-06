"""Static manuscript content (references, authors, descriptive tables) merged with values_auto.json -> values.json."""
import json

import yaml

cfg = yaml.safe_load(open("../configs/default.yaml"))
auto = json.load(open("values_auto.json"))

refs = {
    # ---- retained from the original reference list (text unchanged) ----
    "guo2022": "H. Guo and X. Yu, “A survey on blockchain technology and its security,” Blockchain Res. Appl., vol. 3, no. 2, p. 100067, Jun. 2022, doi: 10.1016/j.bcra.2022.100067.",
    "feng2019": "Q. Feng, D. He, S. Zeadally, M. K. Khan, and N. Kumar, “A survey on privacy protection in blockchain system,” J. Netw. Comput. Appl., vol. 126, pp. 45–58, Jan. 2019, doi: 10.1016/j.jnca.2018.10.020.",
    "ayyagari2021": "M. R. Ayyagari, N. Kesswani, M. Kumar, and K. Kumar, “Intrusion detection techniques in network environment: a systematic review,” Wirel. Netw., vol. 27, no. 2, pp. 1269–1285, Feb. 2021, doi: 10.1007/s11276-020-02529-3.",
    "babu2022": "E. S. Babu et al., “Blockchain-based Intrusion Detection System of IoT urban data with device authentication against DDoS attacks,” Comput. Electr. Eng., vol. 103, p. 108287, Oct. 2022, doi: 10.1016/j.compeleceng.2022.108287.",
    "meng2018": "W. Meng, E. W. Tischhauser, Q. Wang, Y. Wang, and J. Han, “When Intrusion Detection Meets Blockchain Technology: A Review,” IEEE Access, vol. 6, pp. 10179–10188, 2018, doi: 10.1109/ACCESS.2018.2799854.",
    "dai2019": "H.-N. Dai, Z. Zheng, and Y. Zhang, “Blockchain for Internet of Things: A Survey,” IEEE Internet Things J., vol. 6, no. 5, pp. 8076–8094, Oct. 2019, doi: 10.1109/JIOT.2019.2920987.",
    "khan2018": "M. A. Khan and K. Salah, “IoT security: Review, blockchain solutions, and open challenges,” Future Gener. Comput. Syst., vol. 82, pp. 395–411, May 2018, doi: 10.1016/j.future.2017.11.022.",
    "li2021": "W. Li, Y. Wang, J. Li, and M. H. Au, “Toward a blockchain-based framework for challenge-based collaborative intrusion detection,” Int. J. Inf. Secur., vol. 20, no. 2, pp. 127–139, Apr. 2021, doi: 10.1007/s10207-020-00488-6.",
    "alkadi2020": "O. Alkadi, N. Moustafa, and B. Turnbull, “A Review of Intrusion Detection and Blockchain Applications in the Cloud: Approaches, Challenges and Solutions,” IEEE Access, vol. 8, pp. 104893–104917, 2020, doi: 10.1109/ACCESS.2020.2999715.",
    "saveetha2022": "D. Saveetha and G. Maragatham, “Design of Blockchain enabled intrusion detection model for detecting security attacks using deep learning,” Pattern Recognit. Lett., vol. 153, pp. 24–28, Jan. 2022, doi: 10.1016/j.patrec.2021.11.023.",
    "khonde2022": "S. R. Khonde and V. Ulagamuthalvi, “Hybrid intrusion detection system using blockchain framework,” EURASIP J. Wirel. Commun. Netw., vol. 2022, no. 1, p. 58, Jun. 2022, doi: 10.1186/s13638-022-02089-4.",
    "alemari2022": "S. Al-E’mari, M. Anbar, Y. Sanjalawe, S. Manickam, and I. Hasbullah, “Intrusion Detection Systems Using Blockchain Technology: A Review, Issues and Challenges,” Comput. Syst. Sci. Eng., vol. 40, no. 1, pp. 87–112, 2022.",
    "li2023": "W. Li, Y. Wang, and J. Li, “A blockchain-enabled collaborative intrusion detection framework for SDN-assisted cyber-physical systems,” Int. J. Inf. Secur., vol. 22, no. 5, pp. 1219–1230, Oct. 2023, doi: 10.1007/s10207-023-00687-x.",
    "selvarajan2023": "S. Selvarajan et al., “An artificial intelligence lightweight blockchain security model for security and privacy in IIoT systems,” J. Cloud Comput., vol. 12, no. 1, p. 38, Mar. 2023, doi: 10.1186/s13677-023-00412-y.",
    "mansour2022": "R. F. Mansour, “Artificial intelligence based optimization with deep learning model for blockchain enabled intrusion detection in CPS environment,” Sci. Rep., vol. 12, Jul. 2022, doi: 10.1038/s41598-022-17043-z.",
    "shafay2023": "M. Shafay, R. W. Ahmad, K. Salah, I. Yaqoob, R. Jayaraman, and M. Omar, “Blockchain for deep learning: review and open challenges,” Clust. Comput., vol. 26, no. 1, pp. 197–221, Feb. 2023, doi: 10.1007/s10586-022-03582-7.",
    "mathew2022": "S. S. Mathew, K. Hayawi, N. A. Dawit, I. Taleb, and Z. Trabelsi, “Integration of blockchain and collaborative intrusion detection for secure data transactions in industrial IoT: a survey,” Clust. Comput., vol. 25, no. 6, pp. 4129–4149, Dec. 2022, doi: 10.1007/s10586-022-03645-9.",
    "khraisat2019": "A. Khraisat, I. Gondal, P. Vamplew, and J. Kamruzzaman, “Survey of intrusion detection systems: techniques, datasets and challenges,” Cybersecurity, vol. 2, no. 1, p. 20, Jul. 2019, doi: 10.1186/s42400-019-0038-7.",
    # ---- new references ----
    "sharafaldin2018": "I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward generating a new intrusion detection dataset and intrusion traffic characterization,” in Proc. 4th Int. Conf. Information Systems Security and Privacy (ICISSP), 2018, pp. 108–116, doi: 10.5220/0006639801080116.",
    "alexopoulos2017": "N. Alexopoulos, E. Vasilomanolakis, N. R. Ivánkó, and M. Mühlhäuser, “Towards blockchain-based collaborative intrusion detection systems,” in Critical Information Infrastructures Security (CRITIS 2017), Lecture Notes in Computer Science, vol. 10707. Cham, Switzerland: Springer, 2018.",
    "biggio2018": "B. Biggio and F. Roli, “Wild patterns: Ten years after the rise of adversarial machine learning,” Pattern Recognit., vol. 84, pp. 317–331, Dec. 2018, doi: 10.1016/j.patcog.2018.07.023.",
    "castro1999": "M. Castro and B. Liskov, “Practical Byzantine fault tolerance,” in Proc. 3rd USENIX Symp. Operating Systems Design and Implementation (OSDI), New Orleans, LA, USA, 1999, pp. 173–186.",
    "engelen2021": "G. Engelen, V. Rimmer, and W. Joosen, “Troubleshooting an intrusion detection dataset: the CICIDS2017 case study,” in Proc. IEEE Security and Privacy Workshops (SPW), 2021, pp. 7–12.",
    "liu2022": "L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, “Error prevalence in NIDS datasets: A case study on CIC-IDS-2017 and CSE-CIC-IDS-2018,” in Proc. IEEE Conf. Communications and Network Security (CNS), 2022.",
    "arp2022": "D. Arp et al., “Dos and don’ts of machine learning in computer security,” in Proc. 31st USENIX Security Symposium, Boston, MA, USA, 2022, pp. 3971–3988.",
    "johnson2001": "D. Johnson, A. Menezes, and S. Vanstone, “The elliptic curve digital signature algorithm (ECDSA),” Int. J. Inf. Secur., vol. 1, no. 1, pp. 36–63, Aug. 2001, doi: 10.1007/s102070100002.",
    "merkle1988": "R. C. Merkle, “A digital signature based on a conventional encryption function,” in Advances in Cryptology (CRYPTO ’87), Lecture Notes in Computer Science, vol. 293. Berlin, Germany: Springer, 1988, pp. 369–378.",
    "androulaki2018": "E. Androulaki et al., “Hyperledger Fabric: a distributed operating system for permissioned blockchains,” in Proc. 13th EuroSys Conf., Porto, Portugal, 2018, Art. no. 30, doi: 10.1145/3190508.3190538.",
    "chen2016": "T. Chen and C. Guestrin, “XGBoost: A scalable tree boosting system,” in Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining, 2016, pp. 785–794, doi: 10.1145/2939672.2939785.",
    "breiman2001": "L. Breiman, “Random forests,” Mach. Learn., vol. 45, no. 1, pp. 5–32, 2001, doi: 10.1023/A:1010933404324.",
    "goldberg1989": "D. E. Goldberg, Genetic Algorithms in Search, Optimization and Machine Learning. Reading, MA, USA: Addison-Wesley, 1989.",
    "pedregosa2011": "F. Pedregosa et al., “Scikit-learn: Machine learning in Python,” J. Mach. Learn. Res., vol. 12, pp. 2825–2830, 2011.",
}
unchanged_refs = ["guo2022", "feng2019", "ayyagari2021", "babu2022", "meng2018", "dai2019", "khan2018", "li2021", "alkadi2020",
                  "saveetha2022", "khonde2022", "alemari2022", "li2023", "selvarajan2023", "shafay2023", "mathew2022", "khraisat2019"]

g, e, s = cfg["ga"], cfg["ensemble"], cfg["signatures"]
tables = {
    "related": {
        "caption": "Summary of related blockchain-based intrusion detection work.",
        "header": ["Work", "Setting", "Role of blockchain", "Validation of shared content against receivers' traffic"],
        "widths": [18, 22, 36, 24],
        "rows": [
            ["Meng et al. (2018)", "Review", "Data sharing and trust in collaborative IDSs", "Not applicable"],
            ["Alexopoulos et al. (2018)", "Collaborative IDS", "Tamper-resistant record of exchanged alerts", "Not addressed"],
            ["Li et al. (2021)", "Challenge-based CIDN", "Records trust evidence among nodes", "Trust from challenges, not content checks"],
            ["Li et al. (2023)", "SDN-assisted CPS", "Collaborative detection framework", "Not addressed"],
            ["Babu et al. (2022)", "IoT urban data", "IDS with PUF-based device authentication", "Device authentication only"],
            ["Khonde and Ulagamuthalvi (2022)", "Distributed hybrid IDS", "Exchange of new attack signatures (Hyperledger)", "Validator checks on signatures"],
            ["This paper", "Distributed hybrid IDS", "Signature exchange with endorsement quorum and PBFT", "Benign-traffic check by every validator; 2f + 1 quorum"],
        ]},
    "sigformat": {
        "caption": "Signature transaction and block formats.",
        "header": ["Element", "Field", "Content"],
        "widths": [16, 22, 62],
        "rows": [
            ["Signature payload", "key", "Integer vector: protocol, destination port and five log2 bins (Section 3.2)"],
            ["", "fields", "Names of the key elements, fixed in the genesis configuration"],
            ["", "support", "Number of flagged flows that share the key (at least 20)"],
            ["", "sig_id", "First 16 hexadecimal digits of SHA-256 of the key"],
            ["", "origin, created", "Initiating site and Unix creation time"],
            ["Transaction", "payload, origin, sig", "Payload, initiator identity, ECDSA P-256 signature over the canonical JSON payload"],
            ["Endorsement", "seq, digest, bitmap, from, sig", "Batch sequence number, SHA-256 of the batch, one accept bit per transaction, validator identity and signature"],
            ["Block header", "height, prev_hash, timestamp", "Position in the chain, SHA-256 digest of the previous header, creation time"],
            ["", "merkle_root, n_tx, seq, digest", "Merkle root of the transactions, transaction count, batch sequence number, SHA-256 of the header"],
            ["Block body", "txs, certs, rejected", "Committed transactions, 2f + 1 endorsements per transaction, identifiers of rejected transactions"],
        ]},
    "hyper": {
        "caption": "Genetic-algorithm and classifier settings (fixed before evaluation).",
        "header": ["Component", "Setting"],
        "widths": [22, 78],
        "rows": [
            ["Genetic algorithm", f"Binary mask over {auto['vals']['n_feat']} features; population {g['population']}; {g['generations']} generations; tournament selection (size {g['tournament_size']}); uniform crossover (rate {g['crossover_rate']}); bit-flip mutation (rate 1/number of features); elitism {g['elitism']}"],
            ["GA fitness", f"Macro-F1 of a Random Forest ({g['fitness_model']['n_estimators']} trees, maximum depth {g['fitness_model']['max_depth']}) on the chronologically last {int(100*g["validation_fraction"])} % of every (day, label) group of the training portion, minus {g['feature_penalty']} per selected feature; up to {g['fitness_subsample']:,} flows sampled for each part".replace(",", " ")],
            ["MLP", f"Quantile normalisation to a normal distribution; hidden layers {tuple(e['mlp']['hidden_layer_sizes'])}; Adam; learning rate {e['mlp']['learning_rate_init']}; L2 penalty {e['mlp']['alpha']}; batch size {e['mlp']['batch_size']}; at most {e['mlp']['max_iter']} epochs with early stopping"],
            ["XGBoost", f"{e['xgb']['n_estimators']} trees; maximum depth {e['xgb']['max_depth']}; learning rate {e['xgb']['learning_rate']}; row and column subsampling {e['xgb']['subsample']}; histogram tree method"],
            ["Random Forest", f"{e['rf']['n_estimators']} trees; unlimited depth; minimum leaf size {e['rf']['min_samples_leaf']}"],
            ["Ensemble", "Majority vote of the three members (threshold 0.5 each); mean probability used as score"],
            ["Signatures", f"Minimum support {s['min_support']}; benign-match tolerance τ = {s['validator_benign_tolerance']}; log2 bins capped at {s['max_bin']}"],
            ["Ledger", f"Blocks of {cfg['ledger']['batch_size']} transactions; endorsement timeout 1 s; quorum 2f + 1"],
        ]},
}
authors = ["Sharad Pratap Singh 1,*, Hanumat Sastry G 1",
           "1 University of Petroleum and Energy Studies, Dehradun, India",
           "* Correspondence: Sharad Pratap Singh, shrd.singh1@gmail.com"]
auto["tables"].update(tables)
out = {"vals": auto["vals"], "tables": auto["tables"], "refs": refs, "authors": authors,
       "unchangedRefs": unchanged_refs, "unchangedHeadings": ["INTRODUCTION", "1 INTRODUCTION", "2 RELATED WORK", "ABSTRACT", "REFERENCES"]}
json.dump(out, open("values.json", "w"), indent=1, ensure_ascii=False)
print("values.json written")
