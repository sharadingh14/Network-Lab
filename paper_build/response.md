!title Response to Reviewers

!para Manuscript ID: 1960105

!para Original title: Blockchain-Based Mechanism for Enhancing Data Security in Intrusion Detection System

!para Revised title: Poisoning-Resistant Signature Sharing for Hybrid Intrusion Detection Using a Permissioned Blockchain Ledger

Dear Editor and Reviewers,

We thank the reviewers for their careful and critical reading of our manuscript. Their comments identified serious problems, and we have responded by rebuilding the study rather than editing the earlier text. In summary:

- We acknowledge that the earlier version followed the architecture of Khonde and Ulagamuthalvi (EURASIP J. Wirel. Commun. Netw., 2022) without adequate attribution, and that its blockchain performance tables and its comparison table reproduced or closely followed values reported in that paper. All of those values have been withdrawn. The revised manuscript states explicitly that the hybrid architecture follows that work (Sections 1 and 2) and claims as new only the poisoning-resistant endorsement rule, the leakage-controlled evaluation, the ablation and the overhead measurements.
- Every number, table and figure in the revised manuscript was produced by new experiments. The complete code, configuration and instructions are provided in the accompanying repository, and the scripts regenerate all results from the public dataset.
- The general background material (benefits and threats of blockchain, types of IDS, block structure of Bitcoin) and the material summarised from survey articles have been removed. The Introduction, Related Work, Methods, Results, Discussion and Conclusion were rewritten.
- The manuscript now follows the order Introduction, Related Work, Materials and Methods, Results, Discussion, Conclusion, and all figure, table and reference numbers are generated automatically and checked.

Reviewer comments are reproduced in italics, followed by our response and the location of the changes. Section, table and figure numbers refer to the revised manuscript. In the version with highlights, new or substantially revised text is highlighted in yellow; because the manuscript was rewritten, most of the text is highlighted.

# RESPONSE TO REVIEWER 2

!comment 2.1 The manuscript presents HBIDS as a novel blockchain-based intrusion-detection mechanism, but the specific technical innovation is unclear. The proposed system appears to combine signature-based detection, anomaly-based detection, ensemble classifiers, and blockchain-based signature sharing. The authors should clearly distinguish the new contribution from existing blockchain-enabled collaborative IDS frameworks.

**Response.** We agree. The two-phase architecture with blockchain-based signature exchange was proposed by Khonde and Ulagamuthalvi (2022), and the revised manuscript says so directly (Section 1, paragraph 3; Section 2, last paragraph but one; Table 1). We no longer claim the architecture as new. The contributions are now stated as: (i) an endorsement rule in which every validator tests each incoming signature against its own benign traffic, with two admission thresholds (2f + 1 and n − f), so that poisoned signatures can be rejected; (ii) a leakage-controlled evaluation on CSE-CIC-IDS2018 with duplicate removal and a chronological split; (iii) an ablation that separates the detector, signature sharing and the ledger; and (iv) measured overhead against a non-blockchain baseline. Table 1 compares the role of blockchain and the validation of shared content across related systems.

**Changes.** Abstract; Section 1 (contribution list); Section 2; Table 1.

!comment 2.2 Blockchain is mainly used to exchange or store attack signatures, but the paper does not clearly show how blockchain improves the actual detection process. The reported accuracy improvement may result from the ensemble classifier or the expanded signature database rather than from blockchain itself. An ablation study comparing IDS with and without blockchain-based signature sharing is necessary.

**Response.** We agree, and the new results confirm the reviewer's expectation. The collaborative experiment (Section 4.3, Table 7, Figure 4) compares no sharing, sharing through an authenticated publish-subscribe channel without a ledger, and sharing through the ledger. Sharing raises the recall on attack families unseen at a site from {{c_isolated_foreign_recall}} % to {{c_pubsub_foreign_recall}} % (publish-subscribe) and {{c_strict_foreign_recall}} % (ledger, n − f policy). The ledger itself does not improve detection: without an attack, publish-subscribe sharing gives higher recall ({{c_pubsub_recall}} % against {{c_strict_recall}} %), because the ledger rejects a small number of honest signatures that would also raise false alarms at some sites. The ledger's benefit appears under poisoning: with publish-subscribe sharing, poisoned signatures raise the false-positive rate of the honest sites to {{c_pubsub_poisoned_far}} %, whereas with the ledger (n − f policy) it is {{c_strict_poisoned_far}} %. We state this conclusion in the Abstract, Section 4.3, Section 5 and Section 6.

**Changes.** Sections 3.5, 3.7, 4.3 and 4.4; Tables 7 to 9; Figures 4 and 5; Section 5.

!comment 2.3 Important details about the HBIDS architecture are missing, including the exact classifiers used in the ensemble, genetic-algorithm configuration, feature-selection procedure, signature format, consensus mechanism, block structure, transaction design, and communication protocol. The current description is not sufficient for independent replication.

**Response.** All of these are now specified. The ensemble is an MLP, XGBoost and a Random Forest with majority voting (the undefined "IRF" of the earlier version was a Random Forest) (Section 3.3). The GA chromosome, fitness function and all settings are in Section 3.3 and Table 3. The signature format, transaction format and block structure are in Section 3.2, Section 3.4 and Table 2. The consensus and communication protocol (endorse, order, commit with PBFT, ECDSA P-256 signatures, TCP messaging) is described step by step in Section 3.4 and Figure 1. The code repository contains the complete implementation and a single configuration file with every parameter.

**Changes.** Sections 3.2 to 3.5; Tables 2 and 3; Figure 1; code repository.

!comment 2.4 The paper uses the IDS2018/CSE-CIC-IDS2018 dataset, but it does not specify the number of records used, attack categories, class distribution, preprocessing steps, selected features, missing-value treatment, or train/test split. Since this dataset is highly imbalanced and contains temporally related traffic, these details are essential.

**Response.** Section 3.6 and Table 4 now report, for each of the six capture days, the attack labels, the raw record count, the records removed for missing or infinite values ({{nan_total_fmt}} in total), exact duplicates ({{dup_total_fmt}}, {{dup_pct}} %), unique benign and attack records, and the sampled counts. The note to Table 4 gives the size and attack count of the training, signature-window and evaluation portions. The candidate features ({{n_feat}}) and the removal of identifier columns are described in Section 3.3; the number of GA-selected features is reported in Section 4.2, and the selected feature lists for each seed are in the repository's result files. The dataset description has also been corrected: CSE-CIC-IDS2018 was produced by the Communications Security Establishment and the Canadian Institute for Cybersecurity and covers seven attack scenarios, not only DDoS, and it is now cited to its original publication.

**Changes.** Section 3.6; Table 4; Section 4.2; reference list.

!comment 2.5 Randomly splitting network-flow records can place highly similar flows from the same attack campaign in both training and test sets, producing overly optimistic results. The authors should use a time-based, scenario-based, or attack-family-based split and explain how duplicate or near-duplicate records were removed.

**Response.** We use two of the suggested designs. First, a time-based split: every (day, label) group is sorted by timestamp and split into the oldest 60 % (training), the next 20 % (signature window) and the newest 20 % (evaluation); evaluation flows identical to training flows are then removed ({{xsplit_removed}} flows). Second, a site-based split in the collaborative experiment: each capture day is a separate site that trains only on its own traffic and is evaluated on attack families it has never seen. Exact duplicates were removed before splitting, and the scale of the problem is now reported: for example, only {{ftp_unique}} of {{ftp_raw_fmt}} FTP brute-force records and {{slowhttp_unique}} of {{slowhttp_raw_fmt}} DoS SlowHTTPTest records are distinct. Near-duplicates are handled by the signature key, which groups flows with the same protocol, port and log-binned counters. We explain in Section 3.6 why the split is chronological within each group rather than at one cut-off time.

**Changes.** Sections 3.6 and 3.7; Table 4.

!comment 2.6 The paper reports 97.6% accuracy and a 1.13% false-alarm rate, but it does not provide a complete confusion matrix, precision, recall, F1-score, ROC-AUC, PR-AUC, or class-specific results. Accuracy alone is inadequate for intrusion detection, especially with imbalanced data.

**Response.** The earlier figures of 97.6 % and 1.13 % have been withdrawn. Table 5 now reports accuracy, precision, recall, F1, false-positive rate, ROC-AUC and mean FP and FN counts for eleven configurations (mean ± standard deviation over three seeds). Table 6 gives recall per attack family, Figure 2 shows ROC and precision-recall curves, and Figure 3 gives the confusion matrix. PR-AUC values are reported in the text and in the repository's result files. The main configuration reaches F1 {{hyb_all_f1_msd}} % and a false-positive rate of {{hyb_all_far_msd}} %.

**Changes.** Section 4.2; Tables 5 and 6; Figures 2 and 3.

!comment 2.7 The manuscript reports a false-alarm rate of 1.13%, but the formula and denominator are not provided. It is unclear whether this represents the false-positive rate, false discovery rate, or another measure. The authors should define the metric mathematically and report false-positive and false-negative counts.

**Response.** The false alarm rate is now defined as the false-positive rate, FPR = FP / (FP + TN), the fraction of benign flows raised as alerts (Section 3.7, Equation 4). All other metrics are defined in Equations 3 and 4, and FP and FN counts are given in Table 5 and Figure 3.

**Changes.** Section 3.7; Table 5; Figure 3.

!comment 2.8 HBIDS is compared with methods published using different datasets, preprocessing procedures, feature sets, and experimental protocols. Therefore, the comparison cannot establish superiority. The authors should reproduce representative baselines under the same dataset split and evaluation conditions.

**Response.** We agree. The cross-paper comparison table and figure have been removed (the cited baselines were evaluated on KDD-derived data, and the values had been taken from another paper). All baselines are now run on the same split and conditions: the signature stage alone, MLP, XGBoost and Random Forest alone, and the ensemble, each with all features and with GA-selected features (Table 5); and, for sharing, no sharing and a non-blockchain publish-subscribe baseline (Table 7). Section 3.7 states that published accuracy values from other datasets are not compared.

**Changes.** Former Table 7 and Figure 11 removed; Tables 5 and 7; Section 3.7.

!comment 2.9 The paper should separately evaluate the signature-based component, anomaly-based component, ensemble classifier, genetic algorithm, blockchain signature sharing, and consensus layer. This would show which components contribute to detection performance and whether blockchain introduces measurable benefits.

**Response.** Done. Table 5 separates the signature stage, each classifier, the ensemble and the GA. The signature stage alone reaches F1 {{sig_f1}} % with very few false positives; the ensemble adds recall on attacks whose flows vary too much for exact keys (DoS and web attacks, Table 6). GA feature selection reduced the feature set to {{ga_nfeat_range}} of {{n_feat}} features and inference time from {{inf_all_us}} to {{inf_ga_us}} µs per flow, but it did not improve accuracy: the hybrid with all features has the better F1 and false-positive rate. We report this negative result. Signature sharing and the consensus layer are separated in Tables 7 to 9: sharing improves detection, and the endorsement and consensus layer limits poisoning.

**Changes.** Sections 4.2 to 4.4; Tables 5 to 9.

!comment 2.10 The paper reports query execution time, validation time, and latency for different transaction volumes, but it does not measure end-to-end IDS detection latency. The evaluation should include packet-processing rate, alert-generation delay, blockchain confirmation delay, throughput, CPU usage, memory consumption, and storage growth.

**Response.** The earlier execution-time and latency tables have been withdrawn. Section 4.6 now reports the detection-path cost (signature lookup {{sig_us}} µs per flow; ensemble {{inf_all_us}} µs per flow, about {{flows_per_s_all}} flows per second on two CPU cores). Section 4.5 and Table 10 report blockchain commit latency (mean and 95th percentile), throughput, data sent, CPU time and ledger storage growth per signature, for 4 to 13 validators, against the publish-subscribe baseline (Figure 6). Memory use of the validator processes is recorded in the result files. We measure flows rather than packets, because the dataset and the detector operate on CICFlowMeter flow records.

**Changes.** Sections 4.5 and 4.6; Table 10; Figure 6.

!comment 2.11 Adding blockchain to an IDS can introduce communication, storage, consensus, and transaction-processing overhead. The paper does not quantify the cost of maintaining the ledger, propagating signatures, validating blocks, or handling multiple nodes. A comparison with a non-blockchain distributed signature-sharing mechanism is required.

**Response.** Section 3.5 defines the non-blockchain baseline (ECDSA-authenticated publish-subscribe), and Section 4.5 compares it with the ledger. With {{o_nmin}} validators, a 50-signature block takes {{o_ledger_4_lat}} ms to commit on the ledger and {{o_pubsub_4_lat}} ms with publish-subscribe; with {{o_nmax}} validators, {{o_ledger_13_lat}} ms and {{o_pubsub_13_lat}} ms. The ledger sends {{o_ledger_13_kib}} KiB per signature against {{o_pubsub_13_kib}} KiB at n = {{o_nmax}}, and stores {{o_ledger_13_store}} KiB per signature at every validator. We conclude that the ledger is affordable for signature sharing, where volumes are small, but it is a real cost.

**Changes.** Sections 3.5 and 4.5; Table 10; Figure 6.

!comment 2.12 The manuscript states that the implementation uses both Hyperledger Fabric and Hyperledger Sawtooth, but the exact experimental setup and comparison criteria are not explained. It is unclear whether both platforms implement the same HBIDS architecture or whether they are evaluated independently. The statement that Sawtooth provides better "accuracy" is technically questionable because blockchain platform choice should not directly determine classifier accuracy.

**Response.** We agree that the platform cannot change classifier accuracy, and the statement has been removed. The Fabric and Sawtooth results have been withdrawn (see the opening of this letter). The revised study uses a single, fully described ledger prototype (Section 3.4), so there is no cross-platform comparison. The environment available for the revision did not allow Fabric or Sawtooth to be deployed. The repository includes a Fabric chaincode that expresses the same endorsement rule, labelled as not executed.

**Changes.** Section 3.4; Section 5 (limitations).

!comment 2.13 The paper does not adequately address malicious or compromised validator nodes, forged attack signatures, poisoning of the shared signature database, collusion among nodes, replay attacks, denial-of-service attacks, Sybil identities, or false reports from participating IDS nodes. These threats are particularly important in a collaborative blockchain-based IDS.

**Response.** Section 3.1 now gives an explicit threat model, and Section 4.4 evaluates the main threats experimentally. Forged signatures are rejected because every transaction and endorsement carries an ECDSA signature checked against the genesis membership list. Poisoning and false reports are tested with {{n_poison}} poisoned signatures built from benign traffic: publish-subscribe accepted {{ps_poison_accepted}} of them, the ledger with the 2f + 1 policy committed {{led_poison_committed}}, and the ledger with the n − f policy committed {{strict_poison_committed}} (Table 8). Malicious and colluding validators are tested in a sweep from k = 0 to 6 (Table 9, Figure 5), which shows where each policy fails. Crashed validators are tested for liveness. Sybil identities are excluded by permissioned membership. Replay of an old transaction cannot add a new signature, because signatures are identified by the hash of their key and duplicates are ignored. A Byzantine primary and denial-of-service attacks on the network are not evaluated; Section 5 lists them as limitations.

**Changes.** Sections 3.1 and 4.4; Tables 8 and 9; Figure 5; Section 5.

!comment 2.14 The manuscript repeatedly suggests that blockchain ensures confidentiality, privacy, and availability. However, blockchain primarily provides integrity, ordering, and tamper evidence. Confidentiality requires encryption and key management, while availability depends on node health, network connectivity, and storage replication. The paper should correct these claims and explain its encryption and key-management mechanisms.

**Response.** We agree and have corrected these claims throughout. The revised manuscript claims integrity, tamper evidence, authenticated membership, agreed ordering and admission control (Section 1, last paragraph but one; Section 5). It states that blockchain does not provide confidentiality and that availability depends on validator health and connectivity. The system does not encrypt signatures; it limits what is shared (signatures and endorsements only, never raw traffic). Key management is limited to ECDSA P-256 key pairs whose public keys are fixed in the genesis configuration; key rotation and revocation are listed as future work. The incorrect statement that IDSs provide confidentiality and availability services has been removed with the old Section 6.3.

**Changes.** Sections 1, 3.1 and 5; former Sections 6.2 to 6.4 removed.

!comment 2.15 The paper claims that HBIDS significantly enhances data security, prevents unauthorized access, and improves resistance to attacks, but these properties are not evaluated through formal security analysis or realistic adversarial experiments. The conclusion should be limited to the demonstrated results and should acknowledge the dataset limitations, lack of real-world deployment, absence of independent validation, and unresolved blockchain overhead.

**Response.** The Conclusion has been rewritten to state only what the experiments show, and Section 5 now lists the limitations the reviewer names: a single benchmark dataset with known labelling problems, sampling forced by memory limits, a single-machine prototype without wide-area delay, no Byzantine primary or view change, no real-world deployment and no independent validation. The adversarial experiments of Section 4.4 replace the earlier unsupported claims; we do not claim a formal security proof.

**Changes.** Sections 5 and 6.

# RESPONSE TO REVIEWER 3

!comment 3.1 The paper contains a fatal scientific and structural flaw; it relies almost entirely on verbatim copying (plagiarism/self-plagiarism) and the summarization of topics and extensive sections from survey articles presenting only very general information without offering a clear scientific contribution to HBIDS. Furthermore, there are explicit errors regarding references, figures, methodology, and academic formatting.

**Response.** We accept this criticism. The earlier version relied on summarised survey material and followed Khonde and Ulagamuthalvi (2022) without adequate attribution, including tables of results. We have (i) removed all survey-derived background sections (former Sections 3.1 to 3.3 and 6.2 to 6.4, Table 2 and Figures 1 to 4 and 12 to 14); (ii) rewritten the remaining text; (iii) attributed the architecture to its source in Sections 1 and 2 and Table 1; (iv) withdrawn every result that was not produced by our own experiments; and (v) replaced them with new experiments whose code and configuration are released. The scientific contribution is now stated precisely in Section 1. The reference list has been checked entry by entry, irrelevant references have been removed, and author names in the text now match the cited works.

**Changes.** Whole manuscript.

!comment 3.2 The research claims to present a system named HBIDS. However, it does not detail the smart contract code, the full consensus mechanism employed, the encryption method, or the precise manner in which signatures are exchanged between the distribution contract and the verification contract.

**Response.** Section 3.4 now gives the complete exchange protocol: submission, endorsement with the benign-traffic check, the admission threshold, PBFT pre-prepare, prepare and commit, and the reply. The transaction-processing logic (the equivalent of the smart contract) is in the repository (hbids/ledger/node.py), together with a Hyperledger Fabric chaincode version of the endorsement rule. Messages are authenticated with ECDSA P-256 and SHA-256; signatures are not encrypted, and Section 5 explains why and states the limits on confidentiality.

**Changes.** Sections 3.4 and 5; Table 2; Figure 1; code repository.

!comment 3.3 The Genetic Algorithm and the ensemble of classifiers (ANN, XGBoost, IRF) are illustrated in Figure 6 at a high level, without specifying hyperparameter values, the data split (train/test), or training details.

**Response.** Table 3 gives the GA and classifier hyperparameters, Section 3.3 describes training and the GA fitness function, and Sections 3.6 and 3.7 describe the data split. The former Figures 5 and 6 have been replaced by a single architecture figure (Figure 1) that matches the text. "IRF" is replaced by "Random Forest".

**Changes.** Sections 3.3, 3.6 and 3.7; Table 3; Figure 1.

!comment 3.4 Line 81 contains the text "...blockchain technology (?)", where a question mark appears, pointing to a reference that is entirely missing.

**Response.** Corrected. Citations are now generated automatically from a single reference database, and the build stops if a citation key is undefined. The missing reference was Al-E'mari et al. (2022), which is now cited correctly.

**Changes.** Section 2; reference list.

!comment 3.5 In Table 7 and Figure 11 (lines 200-202), the diagram and table cite references [48] and [49], whereas the final reference list in the original paper contains only 26 references (numbered [1] through [26])! This demonstrates direct "cut-and-paste" from another paper without review.

**Response.** We acknowledge this error. Table 7 and Figure 11 have been removed together with the comparison values, which had been taken from another paper (see our response to Comment 3.1 and Reviewer 2, Comment 2.8).

**Changes.** Former Table 7 and Figure 11 removed.

!comment 3.6 The "Materials and Methods" section appears as Section 6, following the Results section (5), the "Proposed Work" section (3), and the "Methodology" section (4). In accordance with academic conventions and Frontiers journal standards, the methodology and data must always precede the results. Furthermore, Sections 6.2, 6.3, and 6.4 contain general, secondary academic explanations regarding the "benefits and challenges of blockchain" and "types of IDS"; these concepts belong in the Introduction or Background section, not within the "Materials and Methods" section.

**Response.** The manuscript has been restructured: 1 Introduction, 2 Related Work, 3 Materials and Methods (system and threat model, method, dataset, evaluation protocol, environment), 4 Results, 5 Discussion, 6 Conclusion. Former Sections 6.2 to 6.4 have been removed; the few concepts needed are introduced briefly in Section 1.

**Changes.** Whole manuscript structure.

!comment 3.7 There are inconsistencies and incorrect references regarding the figures and tables. Line 151 refers to Figures 8 and 9 ("Figure 8 depicts... Figure 9 depicts..."), whereas the relevant figures are actually Figures 5 and 6. Similarly, line 187 refers to Figure 12 for latency, while the corresponding plot is actually Figure 9.

**Response.** Corrected. Figures and tables are numbered automatically in order of appearance, every figure and table is cited in the text, and all cross-references were checked against the final numbering.

**Changes.** Whole manuscript.

!comment 3.8 Attention must be paid to the quality of the shapes.

**Response.** All figures are new. They are generated by the released scripts at 300 dpi, with labelled axes, units and legends; 3-D charts have been replaced by two-dimensional plots, and the stacked bar chart of accuracy and false alarm rate has been removed.

**Changes.** Figures 1 to 6.

!comment 3.9 A comprehensive linguistic and grammatical review must be conducted.

**Response.** The manuscript has been rewritten and edited for language, with attention to consistent terminology and to removing unclear wording from the earlier version.

**Changes.** Whole manuscript.

We thank the reviewers again. We believe the revised manuscript now states its contribution accurately, attributes prior work properly and supports every claim with reproducible experiments.

Sincerely,

Sharad Pratap Singh and Hanumat Sastry G
